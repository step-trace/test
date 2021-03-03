#include <iostream>
#include <stdio.h>
#include <cstring>
#include <conio.h>

typedef unsigned int DWORD;
typedef unsigned long long QWORD;

int main(int argc, char* argv[]){
	QWORD addr;
	//ассемблерная вставка призвана определить местоположение 
	//метки label (то есть самого кода) в оперативной памяти
    asm ("label:\n\t"				//метка по сути является адресом в памяти
		 "movq $label, %%rax\n\t" 	//помещаем адрес метки(то есть адрес 
									//текущей инструкции) в регистр rax
         "movq %%rax, %0\n\t"		//копируем содержимое регистра rax в первую 
									//переданную переменную
          :"=r"(addr)   			//передаем переменную, в которую записать значение 
									//(ключ "=r" указывает,что адрес переменной 
									//можно поместить в любой регистр и эта переменная 
									//используется только для записи)
          :         	
          :"%rax"       			//освобождаем rax. но это не точно
    );
	addr = addr & 0xFFFFFFFFFFFFF000;	//обнуляем младшие 12 бит для выравнивания
	short sign; 						
	while (sign != 0x5a4d) {			//0x4D5A MZ - сингатура исполняемого файла
		sign = *(short*)addr;
		addr -= 0x1000;
	}
	QWORD image_base = addr + 0x1000;
	//std::cout << image_base;
	addr = image_base + 0x3C; 			//3С - смещение до значения смещения NT заголовка
	DWORD nt_header_offset = *(DWORD*)addr;
	addr = image_base + nt_header_offset; //получаем адрес NT Header
	//std::cout << nt_header_offset;
	DWORD nt_sign = *(DWORD*)addr;
	if (nt_sign != 0x4550){				//0x50450000 == PE - сигнатура NT header
		std::cout << "Error!";
		return 1;
	}
	QWORD nt_header_addr = addr;
	char offset_to_opt_header = 0x18;	//+0x18 - смещение до OptionalHeader,
										//в начале которого инфа о формате файла
										//(4б сигнатуры + 0x14б sizeof(File Header))
	short fmt = *(short *)(nt_header_addr + offset_to_opt_header); 										    
	//std::cout << fmt;
	short opt_header_size;				//размер опционального заголовка без учета Data Directories
	if (fmt == 0x10B) opt_header_size = 0x60;		//0x10B соответствует формату PE32
	else if (fmt == 0x20B) opt_header_size = 0x70;	//0x20B соответствует формату PE32+
	else {
		std::cout << "Error!";
		return 1;
	}
	//std::cout << opt_header_size;
	struct DATA_DIRECTORY {
		DWORD RVA;
		DWORD Size;
	};
	DATA_DIRECTORY* data_directory = (DATA_DIRECTORY*)(nt_header_addr + offset_to_opt_header + opt_header_size);
	//std::cout << data_directory[1].RVA;
	QWORD import_table_addr = image_base + data_directory[1].RVA;
	struct IMAGE_IMPORT_DESCRIPTOR {
		union {
			DWORD   Characteristics;
			DWORD   OriginalFirstThunk; 
		};
		DWORD   TimeDateStamp;
		DWORD   ForwarderChain;
		DWORD   Name;
		DWORD   FirstThunk;
	};
	//создаем и инициализируем указатель на массив структур IMAGE_IMPORT_DESCRIPTOR
	IMAGE_IMPORT_DESCRIPTOR* img_import_desc = (IMAGE_IMPORT_DESCRIPTOR*)import_table_addr;
	int i = 0;  //счетчик
	int n = 0;	//порядковый номер элемента в массиве IMAGE_IMPORT_DESCRIPTOR,
				//соответствующего нужной библиотеке
	std::cout << "Get imported Dll's names:\n";
	char dll_name[] = "KERNEL32.dll";
	//проходим по всем элементам массива, пока не встретим нулевой
	while (img_import_desc[i].Name != 0){
		printf("%s\n", (image_base + img_import_desc[i].Name));
		//сравниваем массивы char'ов (имена библиотек)
		if(strcmp((char*)(image_base + img_import_desc[i].Name), dll_name) == 0) n = i; 
		i++;
	}
	//получаем адрес(указатель) массива IMAGE_THUNK_DATA,
	//где каждый элемент является указателем на struct{short Hint;char func_Name[]} 
	QWORD* OriginalFirstThunk_arr = (QWORD*)(image_base + img_import_desc[n].OriginalFirstThunk);
	//OriginalFirstThunk_arr - указатель на неизменный массив IMAGE_THUNK_DATA
	QWORD *FirstThunk_arr = (QWORD *)(image_base + img_import_desc[n].FirstThunk);
	//FirstThunk_arr - указатель на массив IMAGE_THUNK_DATA, в котором адреса будут заменены
	char* import_func_name;
	i = 0;
	n = 0;
	std::cout << "\nGet imported functions names:\n";
	char our_func_name[] = "GetCurrentProcessId";
	while (OriginalFirstThunk_arr[i] != 0){
		import_func_name = (char*)(image_base + OriginalFirstThunk_arr[i] + 2); //+ 2 байта (размер Hint)
		printf("%s\n", import_func_name);
		if(strcmp(import_func_name, our_func_name) == 0) n = i;
		i++;
	}
	QWORD our_func_addr = FirstThunk_arr[n];
	DWORD (*get_process_id)();						//объявляем указатель на функцию
	get_process_id = (DWORD(*)())our_func_addr;		//приводим адрес к нужному типу
	DWORD process_id = get_process_id();			//и вызываем функцию
	std::cout << process_id;
	getch();
	return 0;
}


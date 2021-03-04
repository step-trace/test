#include <iostream>
#include <stdio.h>
#include <cstring>
#include <conio.h>

typedef unsigned short WORD;
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
	std::cout << "Process ID: " << process_id << "\n";
	//начинаем парсинг KERNEL32.dll
	//зная адрес одной из функций, может найти адрес, по которому 
	//библиотека загрузилась в память
	addr = our_func_addr & 0xFFFFFFFFFFFFF000; 		//выравниваем по 4кб границе
	sign = 0;
	while (sign != 0x5a4d) {			//0x4D5A MZ - сингатура исполняемого файла
		sign = *(short*)addr;
		addr -= 0x1000;
	}
	QWORD kernel32_image_base = addr + 0x1000;
	printf("Kernel32.dll ImageBase == %p\n", kernel32_image_base);
	//теперь нужно получить адрес массива DATA Directories
	addr = kernel32_image_base + 0x3C; 			//3С - смещение до значения смещения NT заголовка
	DWORD dll_nt_header_offset = *(DWORD*)addr;
	addr = kernel32_image_base + dll_nt_header_offset; //получаем адрес NT Header
	nt_sign = *(DWORD*)addr;
	if (nt_sign != 0x4550){				//0x50450000 == PE - сигнатура NT header
		std::cout << "Error! krnl32.nt_sign";
		return 1;
	}
	QWORD dll_nt_header_addr = addr;
	fmt = *(short *)(dll_nt_header_addr + offset_to_opt_header); 										    
	if (fmt == 0x10B) opt_header_size = 0x60;		//0x10B соответствует формату PE32
	else if (fmt == 0x20B) opt_header_size = 0x70;	//0x20B соответствует формату PE32+
	else {
		std::cout << "Error! krnl32.fmt";
		return 1;
	}
	DATA_DIRECTORY* dll_data_directory = (DATA_DIRECTORY*)(dll_nt_header_addr + offset_to_opt_header + opt_header_size);
	//0-й элемент массива - RVA таблицы экспорта
	//В тaблице экспорта нас интересуют 
	//NumberOfFunctions (по смещению 0x14) (DWORD)
	//NumberOfNames (по смещению 0x18) (DWORD)
	//AddressesOfFunctions (по смещению 0x1C) - RVA адрес массива(DWORD) RVA адресов функций (DWORD)
	//AddressesOfNames (по смещению 0x20) - RVA адрес массива(DWORD) RVA адресов имен функций(DWORD)
	//AddressesOfOrdinals (по смещению 0x24) - RVA адрес массива(DWORD) ординалов (WORD)
	QWORD export_tbl_addr = kernel32_image_base + dll_data_directory[0].RVA;
	DWORD NumberOfFunctions = *(DWORD*)(export_tbl_addr + 0x14);
	DWORD NumberOfNames = *(DWORD*)(export_tbl_addr + 0x18);
	std::cout << "nFunctions: " << NumberOfFunctions << "  nNames: " << NumberOfNames << "\n";
	DWORD* AddressesOfFunctions = (DWORD*)(kernel32_image_base + *(DWORD*)(export_tbl_addr + 0x1C));
	DWORD* AddressesOfNames = (DWORD*)(kernel32_image_base + *(DWORD*)(export_tbl_addr + 0x20));
	WORD* AddressesOfOrdinals = (WORD*)(kernel32_image_base + *(DWORD*)(export_tbl_addr + 0x24));
	//printf("Kernel32.dll AddressesOfNames[0] RVA == %p\n", AddressesOfNames[0]);
	//printf("Kernel32.dll AddressesOfNames[0] VA == %p\n", kernel32_image_base + AddressesOfNames[0]);
	//ищем функции LoadLibraryA и GetProcAddress
	//а адрес функции находится по так if (names[n] == "funcName") funcAddr = addresses[ordinals[n]]
	char load_lib[] = "LoadLibraryA";
	char get_proc[] = "GetProcAddress";
	int load_lib_idx;
	int get_proc_idx;
	for (i = 0; i < NumberOfNames; i++){
			import_func_name = (char*)(kernel32_image_base + AddressesOfNames[i]);
			if(strcmp(import_func_name, load_lib) == 0) load_lib_idx = i;
			if(strcmp(import_func_name, get_proc) == 0) get_proc_idx = i;
	}
	std::cout << "load_lib_idx: " << load_lib_idx << "  get_proc_idx: " << get_proc_idx << "\n";
	load_lib_idx = AddressesOfOrdinals[load_lib_idx];
	get_proc_idx = AddressesOfOrdinals[get_proc_idx];
	std::cout << "load_lib_idx: " << load_lib_idx << "  get_proc_idx: " << get_proc_idx << "\n";
	QWORD load_lib_addr = kernel32_image_base + AddressesOfFunctions[load_lib_idx];
	QWORD get_proc_addr = kernel32_image_base + AddressesOfFunctions[get_proc_idx];
	printf("Kernel32.dll load_lib_addr == %p\n", load_lib_addr);
	printf("Kernel32.dll get_proc_addr == %p\n", get_proc_addr);
	//HMODULE LoadLibraryA(LPCSTR lpLibFileName); - prototype
	QWORD (*LoadLibraryA)(const char*);
	LoadLibraryA = (QWORD(*)(const char*))load_lib_addr;
	//FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName); - prototype
	QWORD (*GetProcAddress)(QWORD, const char*);
	GetProcAddress = (QWORD(*)(QWORD, const char*))get_proc_addr;
	const char user32dll[] = "USER32.dll";
	QWORD hModule = LoadLibraryA(user32dll);
	const char message_box[] = "MessageBoxA";
	QWORD message_box_addr = GetProcAddress(hModule, message_box);
	printf("Kernel32.dll message_box_addr == %p\n", message_box_addr);
	//int MessageBoxA(HWND   hWnd = 0 //no parent, LPCSTR lpText, LPCSTR lpCaption, UINT uType = 0 //MB_ok); - prototype
	int (*MessageBoxA)(QWORD, const char*, const char*, DWORD);
	MessageBoxA = (int(*)(QWORD, const char*, const char*, DWORD))message_box_addr;
	const char message[] = "We did it!!!";
	const char caption[] = "Congratulations!";
	int result = MessageBoxA(0, message, caption, 0);
	getch();
	return result;
}


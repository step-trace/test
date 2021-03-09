#include <iostream>
#include <stdio.h>
#include <cstring>
#include <conio.h>

typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned long long QWORD;

struct DATA_DIRECTORY {
	DWORD RVA;
	DWORD Size;
};

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

QWORD getImageBase(QWORD address){
	address = address & 0xFFFFFFFFFFFFF000;	//обнуляем младшие 12 бит для выравнивания
	WORD sign; 						
	while (sign != 0x5a4d) {			//0x4D5A MZ - сингатура исполняемого файла
		sign = *(WORD*)address;
		address -= 0x1000;
	}
	address = address + 0x1000;
	return address;
}
	
QWORD getDataDirectoryAddress(QWORD imageBase){
	QWORD address;
	address = imageBase + 0x3C; 			//3С - смещение до значения смещения NT заголовка
	DWORD nt_header_offset = *(DWORD*)address;
	address = imageBase + nt_header_offset; //получаем адрес NT Header
	DWORD nt_sign = *(DWORD*)address;
	if (nt_sign != 0x4550){				//0x50450000 == PE - сигнатура NT header
		std::cout << "Error!";
		return 1;
	}
	QWORD nt_header_addr = address;
	char offset_to_opt_header = 0x18;	//+0x18 - смещение до OptionalHeader,
										//в начале которого инфа о формате файла
										//(4б сигнатуры + 0x14б sizeof(File Header))
	WORD fmt = *(WORD *)(nt_header_addr + offset_to_opt_header); 										    
	WORD opt_header_size;				//размер опционального заголовка без учета Data Directories
	if (fmt == 0x10B) opt_header_size = 0x60;		//0x10B соответствует формату PE32
	else if (fmt == 0x20B) opt_header_size = 0x70;	//0x20B соответствует формату PE32+
	else {
		std::cout << "Error!";
		return 1;
	}
	return (nt_header_addr + offset_to_opt_header + opt_header_size);
}

int main(int argc, char* argv[]){
	QWORD addr;
	addr = (QWORD)main; 				//получаем адрес main в оперативной памяти
	QWORD image_base = getImageBase(addr);
	DATA_DIRECTORY* data_directory = (DATA_DIRECTORY*)getDataDirectoryAddress(image_base);
	QWORD import_table_addr = image_base + data_directory[1].RVA;
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
	std::cout << "Process ID: " << process_id << "\n\n";
	//начинаем парсинг KERNEL32.dll
	//зная адрес одной из функций, может найти адрес, по которому 
	//библиотека загрузилась в память
	QWORD kernel32_image_base = getImageBase(our_func_addr);
	printf("Kernel32.dll ImageBase == %p\n", kernel32_image_base);
	//теперь нужно получить адрес массива DATA Directories
	DATA_DIRECTORY* dll_data_directory = (DATA_DIRECTORY*)getDataDirectoryAddress(kernel32_image_base);
	//0-й элемент массива - RVA и размер таблицы экспорта
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
	//ищем функции LoadLibraryA и GetProcAddress
	//а адрес функции находится так: if (names[n] == "funcName") funcAddr = addresses[ordinals[n]]
	char load_lib[] = "LoadLibraryA";
	char get_proc[] = "GetProcAddress";
	int load_lib_idx;
	int get_proc_idx;
	for (i = 0; i < NumberOfNames; i++){
			import_func_name = (char*)(kernel32_image_base + AddressesOfNames[i]);
			if(strcmp(import_func_name, load_lib) == 0) load_lib_idx = i;
			if(strcmp(import_func_name, get_proc) == 0) get_proc_idx = i;
	}
	load_lib_idx = AddressesOfOrdinals[load_lib_idx];
	get_proc_idx = AddressesOfOrdinals[get_proc_idx];
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


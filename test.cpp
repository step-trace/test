#include <iostream>
#include <stdio.h>

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
	while (sign != 0x5a4d) {			//0x5a4d MZ - сингатура исполняемого файла
		sign = *(short*)addr;
		addr -= 0x1000;
	}
	QWORD image_base = addr + 0x1000;
	//std::cout << image_base;
	return 0;
}


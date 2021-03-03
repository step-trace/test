#include <stdio.h>
#include <typeinfo>
#include <iostream>

int main(int argc, char* argv[]){
	int line[3] = {1,2,3};
	int square[2][2] = {
		{1, 2},
		{3, 4}
	};
	int cube[3][3][3] = {
		{{1, 2, 3}, {4, 5, 6},{7, 8, 9}},
		{{10, 11, 12}, {13, 14, 15},{16, 17, 18}},
		{{19, 20, 21}, {22, 23, 24},{25, 26, 27}}
	};
	std::cout << "int line[3];\nint square[2][2];\nint cube[3][3][3];" << '\n';
	std::cout << "1: line has type: " << typeid(line).name() << '\n';
	std::cout << "   square has type: " << typeid(square).name() << '\n';
	std::cout << "   cube has type: " << typeid(cube).name() << '\n';
	std::cout << "2: &line has type: " << typeid(&line).name() << '\n';
	std::cout << "   &square has type: " << typeid(&square).name() << '\n';
	std::cout << "   &cube has type: " << typeid(&cube).name() << '\n';
	std::cout << "3: &line[0] has type: " << typeid(&line[0]).name() << '\n';
	std::cout << "   &square[0][0] has type: " << typeid(&square[0][0]).name() << '\n';
	std::cout << "   &cube[0][0][0] has type: " << typeid(&cube[0][0][0]).name() << '\n';
	std::cout << "3: *line has type: " << typeid(*line).name() << '\n';
	std::cout << "   *square has type: " << typeid(*square).name() << '\n';
	std::cout << "   *cube has type: " << typeid(*cube).name() << '\n';
	std::cout << '\n';
	printf("line == %p   &line == %p   &line[0] == %p\n", line, &line, &line[0]);
	printf("square == %p   &square == %p   &square[0][0] == %p\n", square, &square, &square[0][0]);
	printf("cube == %p   &cube == %p   &cube[0][0][0] == %p\n", cube, &cube, &cube[0][0][0]);
	std::cout << "Same values, but not types!!!" << '\n';
	std::cout << '\n';
	std::cout << "cube has type: " << typeid(cube).name() << '\n';
	std::cout << "(cube+1) has type: " << typeid((cube+1)).name() << '\n';
	std::cout << '\n';
	std::cout << "cube has type: A3_A3_A3_i   and   (cube+1) has type: PA3_A3_i   ???" << '\n';
	std::cout << "Looks like compiler has done some shadow operations (converting types)." << '\n';
	std::cout << '\n';
	std::cout << "My thoughts" << '\n';
	std::cout << "At first compiler converts 'cube' to the pointer to the beginning of the array (&cube[0][0][0])\n";
	std::cout << "Then, adds offset equal to c * sizeof(int_array[3][3]) \n";
	std::cout << "At the end compiler perfoms typecasting to the pointer to (int*[3][3])\n";
	std::cout << "Somthing like this: (cube + c) == (int*[3][3])((char*)&cube[0][0][0] + c * sizeof(int_array[3][3]))";
	//В записи (cube + 1) компилятор сначала преобразует cube в указатель на начало массива,
	//затем отступает от начала массива на величину = 1 * sizeof(A3_A3_i) (1 * размер_двумерного_массива)
	//потом полученный адрес приводит к типу указатель_на_двумерный массив (int* [3][3]).
	//то есть (cube + c) == (int*[3][3])((char*)&cube[0][0][0] + c * sizeof(cube[0]))	
	return 0;
}
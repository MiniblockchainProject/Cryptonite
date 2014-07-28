#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

static const uint64_t COIN = 100000000;

void to_string(uint64_t v){
	uint64_t whole = v / COIN;
	uint64_t fraction = v - (whole*COIN);
	printf("%ld.", whole);

	int i;
	for(i=0; i < ceil(log10(COIN)); i++){
		fraction *= 10;
		printf("%c", '0' + (fraction/COIN));
		fraction -= (fraction/COIN)*COIN;
	}

	printf("ep\n");
}

uint64_t from_string(const char* str){
	int end = strlen(str);
	if(end < 12){
		//error
		return 0;
	}
	if(str[end-2] != 'e' || str[end-1] != 'p'){
		//error
		return 0;
	}
	uint64_t v;	
	int i;	
	for(i=0; i < end-2; i++){
		char c = str[i];
		if(i==end-11){
			if(c == '.')
				continue;
			//error
			return 0;
		}
		if(c < '0' || c > '9'){
			//error
			return 0;
		}
		v = v * 10 + (c - '0');	
	}

	return v;
}

int main(){
	to_string(((uint64_t)(COIN*5006877854.011119876543))+1);
	printf("%f",from_string("5006877854.01112002ep")/(double)COIN);
	return 0;
}

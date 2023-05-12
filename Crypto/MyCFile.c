//
//  MyCFile.c
//  Crypto
//
//  Created by SEOJIN HONG on 2023/05/12.
//

#include "MyCFile.h"

int sum(int a, int b) {
    return a + b;
}

void printByte(void) {
    
    int length = 10;
    
    unsigned char byteArray[length];
    
    for (int i = 0; i < length; i++) {
        byteArray[i] = i;
    }
    
    // 배열에 저장된 값을 출력합니다.
    for(int i = 0; i < length; i++) {
        printf("%d ", byteArray[i]);
    }
    
    printf("\n");
}

void printByte2(void) {
    unsigned char byteArray[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    int i;
    
    for (i = 0; i < sizeof(byteArray); i++) {
        printf("%02x ", byteArray[i]);
    }
    printf("\n");
}

#include "des.h"

void DES::ShiftLeftHalfKey(bool key[DES_KEY_SIZE / 2])
{
    bool var = key[0];
    int counter;
    for(counter = 0; counter < DES_KEY_SIZE / 2 - 1; ++counter)
        key[counter] = key[counter + 1];
    key[DES_KEY_SIZE / 2 - 1] = var;
}


void DES::GenerateKeys(const bool buffer[DES_DATA_SIZE])
{
    bool key[DES_DATA_SIZE];
    int counter;
    for(counter = 0; counter < DES_KEY_SIZE; ++counter)
    {
        key[counter] = buffer[PASSWORD_PERMUTATION[counter] - 1];
    }
    InitializeKeys(key);
}


void DES::InitializeKeys(const bool key[DES_KEY_SIZE])
{
    int round;
    int counter;
    bool shiftedKey[DES_KEY_SIZE];
    memcpy(shiftedKey, key, DES_KEY_SIZE);

    for (round = 0; round < DES_ROUNDS; round++)
    {
        ShiftLeftHalfKey(shiftedKey);
        ShiftLeftHalfKey(shiftedKey + DES_KEY_SIZE / 2);

        if (KEY_SHIFT[round] == 2)
        {
            ShiftLeftHalfKey(shiftedKey);
            ShiftLeftHalfKey(shiftedKey + DES_KEY_SIZE / 2);
        }

        for (counter = 0; counter < DES_SBUFFER_SIZE; counter++)
        {
            CompressedShiftedKeys[round][counter] = shiftedKey[COMPRESSION_PERMUTATION[counter] - 1];
        }
    }
}

void DES::PasswordExpansion(char passwordString[DES_KEY_SIZE / 8],\
                            bool passwordBuffer[DES_DATA_SIZE])
{
    int counter;
    int bitCounter;
    int shift;
    bool noParityBit;
    char *symbolPointer = passwordString;
    for(counter = 0, bitCounter = 7, noParityBit = 0, shift = 7; counter < DES_KEY_SIZE; ++counter)
    {
        if(bitCounter)
        {
            passwordBuffer[counter] = symbolPointer[0] >> shift & 1;
            if(shift)
            {
                shift--;
            }
            else
            {
                symbolPointer++;
                shift = 7;
            }
            noParityBit ^= passwordBuffer[counter];
            bitCounter--;
        }
        else
        {
            passwordBuffer[counter] = !noParityBit;
            noParityBit = 0;
            bitCounter = 7;
        }
    }
}

void DES::EncryptDecrypt(bool data[],bool encryptFlag)
{
    bool buffer[DES_DATA_SIZE];
    bool sBuffer[DES_SBUFFER_SIZE];
    bool pBuffer[DES_DATA_SIZE / 2];

    int round;
    int counter;

    unsigned char var;

    /*Начальная перестановка данных*/
    for(counter = 0; counter < DES_DATA_SIZE; counter++)
        buffer[counter] = data[INITIAL_PERMUTATION[counter] - 1];

    for (round = 0; round < DES_ROUNDS; round++)
    {
    /* Расширение правого блока и побитовое сложение с ключом */
        for (counter = 0; counter < DES_SBUFFER_SIZE; counter++)
        {
            sBuffer[counter] = buffer[DES_DATA_SIZE / 2  - 1 + EXPANSION_PERMUTATION[counter]] ^ \
                    CompressedShiftedKeys[encryptFlag ? round : ((DES_ROUNDS - 1) - round)][counter];
        }
    /* Преобразование через S-блоки */
        unsigned char xTab;
        unsigned char yTab;
        unsigned char result;
        for (counter = 0; counter < 8; counter++)
        {
            xTab = ((sBuffer[counter * 6 + 0] << 1) | sBuffer[counter * 6 + 5]);
            yTab = ((sBuffer[counter * 6 + 1] << 3) | (sBuffer[counter * 6 + 2] << 2)\
                    | (sBuffer[counter * 6 + 3] << 1) | sBuffer[counter * 6 + 4]);

            result = SBOX[(counter * 8) * (16 * 4) + xTab * 16 + yTab];

            pBuffer[counter * 4 + 0] = result >> 3 & 1;
            pBuffer[counter * 4 + 1] = result >> 2 & 1;
            pBuffer[counter * 4 + 2] = result >> 1 & 1;
            pBuffer[counter * 4 + 3] = result & 1;
        }
        /* R(i) = L(i-1) xor F(R(i-1),k(i))
           L(i) = R(i-1) */
        if (round < DES_ROUNDS - 1)
        {
            for (counter = 0; counter < DES_DATA_SIZE / 2; counter++)
            {
                var = buffer[DES_DATA_SIZE / 2 + counter];
                buffer[DES_DATA_SIZE / 2 + counter] = buffer[counter]\
                        ^ pBuffer[PBOX_PERMUTATION[counter] - 1];
                buffer[counter] = var;
            }
        }
        else
        {
            for (counter = 0; counter < DES_DATA_SIZE / 2; counter++)
                buffer[counter] = buffer[counter] ^ pBuffer[PBOX_PERMUTATION[counter] - 1];
        }
    }
    /*Конечная перестановка данных*/
    for(counter = 0; counter < DES_DATA_SIZE; counter++)
        data[counter] = buffer[FINAL_PERMUTATION[counter] - 1];
}

void DES::Modes(bool data[DES_DATA_SIZE], bool vector[DES_DATA_SIZE])
{
    bool buffer[DES_DATA_SIZE];
    int counter;
    switch(ModeIndex)
    {
    case 0://ECB
        EncryptDecrypt(data, EncryptDecryptFlag);
        break;
    case 1://CBC
        if(EncryptDecryptFlag)
        {
            for(counter = 0; counter < DES_DATA_SIZE; ++counter)
                data[counter] ^= vector[counter];
            EncryptDecrypt(data, EncryptDecryptFlag);
            memcpy(vector, data, DES_DATA_SIZE);
        }
        else
        {
            memcpy(buffer, data, DES_DATA_SIZE);
            EncryptDecrypt(data, EncryptDecryptFlag);
            for(counter = 0; counter < DES_DATA_SIZE; ++counter)
            {
                data[counter] ^= vector[counter];
            }
            memcpy(vector, buffer, DES_DATA_SIZE);
        }
        break;
    case 2://CFB
        EncryptDecrypt(vector, 1);
        if(EncryptDecryptFlag)
        {
            for(counter = 0; counter < DES_DATA_SIZE; ++counter)
            {
                data[counter] ^= vector[counter];
            }
            memcpy(vector, data, DES_DATA_SIZE);
        }
        else
        {
            memcpy(buffer, data, DES_DATA_SIZE);
            for(counter = 0; counter < DES_DATA_SIZE; ++counter)
            {
                data[counter] ^= vector[counter];
            }
            memcpy(vector, buffer, DES_DATA_SIZE);
        }
        break;
    case 3://OFB
        EncryptDecrypt(vector, 1);
        for(counter = 0; counter < DES_DATA_SIZE; ++counter)
            data[counter] ^= vector[counter];
        break;
    }
}

int DES::MainDES(QFile *inputFile, QFile *keyFile,\
                 QFile *outputFile, QFile *vectorFile)
{
    int size;
    int counter;
    bool buffer[DES_DATA_SIZE];
    bool vectorBuffer[DES_DATA_SIZE];
    bool endReadFlag = 0;
    bool firstReadFlag = 1;
    char InputByteBuffer[DES_DATA_SIZE / 8];
    char OutputByteBuffer[DES_DATA_SIZE / 8];
    char password[DES_KEY_SIZE / 8];

    if((size = keyFile->read(password, DES_KEY_SIZE / 8)) < DES_KEY_SIZE / 8)
        for(counter = size; counter < DES_KEY_SIZE / 8; ++counter)
            password[counter] = 0;

    PasswordExpansion(password, buffer);//Расширение пароля битами четности
    GenerateKeys(buffer);

    if(ModeIndex)
    {
        if((size = vectorFile->read(InputByteBuffer, DES_DATA_SIZE / 8)) < DES_DATA_SIZE / 8)
            for(counter = size; counter < DES_DATA_SIZE / 8; ++counter)
                InputByteBuffer[counter] = 0;
        for(counter = 0; counter < DES_DATA_SIZE / 8; ++counter)
        {
            vectorBuffer[counter * 8 + 0] = InputByteBuffer[counter] >> 7 & 1;
            vectorBuffer[counter * 8 + 1] = InputByteBuffer[counter] >> 6 & 1;
            vectorBuffer[counter * 8 + 2] = InputByteBuffer[counter] >> 5 & 1;
            vectorBuffer[counter * 8 + 3] = InputByteBuffer[counter] >> 4 & 1;
            vectorBuffer[counter * 8 + 4] = InputByteBuffer[counter] >> 3 & 1;
            vectorBuffer[counter * 8 + 5] = InputByteBuffer[counter] >> 2 & 1;
            vectorBuffer[counter * 8 + 6] = InputByteBuffer[counter] >> 1 & 1;
            vectorBuffer[counter * 8 + 7] = InputByteBuffer[counter] & 1;
        }
    }

    while (!endReadFlag)
    {
        if((size = inputFile->read(InputByteBuffer, DES_DATA_SIZE / 8)) < DES_DATA_SIZE / 8)
        {
            endReadFlag = 1;
            for(counter = size; counter < DES_DATA_SIZE / 8; ++counter)
                InputByteBuffer[counter] = 0;
            InputByteBuffer[DES_DATA_SIZE / 8 - 1] = 8 - size;
        }

        for(counter = 0; counter < DES_DATA_SIZE / 8; ++counter)
        {
            buffer[counter * 8 + 0] = InputByteBuffer[counter] >> 7 & 1;
            buffer[counter * 8 + 1] = InputByteBuffer[counter] >> 6 & 1;
            buffer[counter * 8 + 2] = InputByteBuffer[counter] >> 5 & 1;
            buffer[counter * 8 + 3] = InputByteBuffer[counter] >> 4 & 1;
            buffer[counter * 8 + 4] = InputByteBuffer[counter] >> 3 & 1;
            buffer[counter * 8 + 5] = InputByteBuffer[counter] >> 2 & 1;
            buffer[counter * 8 + 6] = InputByteBuffer[counter] >> 1 & 1;
            buffer[counter * 8 + 7] = InputByteBuffer[counter] & 1;
        }

        if(endReadFlag && !EncryptDecryptFlag)
        {
            if(size)
            {
                ErrorStr = "Unexpected end of file\n";
                return 1;
            }
            else
            {
                outputFile->write(OutputByteBuffer,\
                                  DES_DATA_SIZE / 8 - OutputByteBuffer[DES_DATA_SIZE / 8 - 1]);
                return 0;
            }
        }
        else
        {
            if(firstReadFlag)
                firstReadFlag = 0;
            else
            {
                outputFile->write(OutputByteBuffer, DES_DATA_SIZE / 8);
            }
            Modes(buffer, vectorBuffer);

            for(counter = 0; counter < DES_DATA_SIZE / 8; ++counter)
            {
                OutputByteBuffer[counter] = (\
                        buffer[counter * 8 + 0] << 7 |\
                        buffer[counter * 8 + 1] << 6 |\
                        buffer[counter * 8 + 2] << 5 |\
                        buffer[counter * 8 + 3] << 4 |\
                        buffer[counter * 8 + 4] << 3 |\
                        buffer[counter * 8 + 5] << 2 |\
                        buffer[counter * 8 + 6] << 1 |\
                        buffer[counter * 8 + 7]);
            } 
        }
        if(endReadFlag)
        {
            outputFile->write(OutputByteBuffer, DES_DATA_SIZE / 8);
        }
    }  
    return 0;
}

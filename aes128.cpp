#include <string.h>
#include <iomanip>
#include "aes128.hpp"

aes128::aes128()
{

}

std::string aes128::enc(std::string user_in, uint8_t*key)
{
    // Заполнение сообщения так, чтобы длина была кратна размеру блока т.е. 16
    uint32_t msg_blen = user_in.length() + 16-user_in.length()%16;
    if(user_in.length()%16 == 0) {
        msg_blen-=16;
    }
    std::stringstream ss;
    ss << user_in << std::setw(msg_blen) << "";
    std::string new_input[msg_blen/16];
    int32_t k=-1;
    std::string final_val = "";

    // Разделение сообщения на блоки по 16
    for(size_t c = 0; c < msg_blen; c+=16) {
        k++;
        if(k < msg_blen/16.0) {
            new_input[k] = ss.str().substr(c,16);
        }
    }
    // Вывод
    for(int c=0;c < msg_blen/16.0;c++) {
        final_val += encrypt_syb(new_input[c], key);
    }
    return final_val;
}

std::string aes128::dec(std::string user_in, uint8_t*key)
{
    std::string new_input[user_in.length()/32];
    int k=-1;
    std::string final_val = "";

    // Разделение сообщения на блоки по 32 шестнадцатеричных цифры
    for(size_t c=0;c < user_in.length();c+=32) {
        k++;
        new_input[k] = user_in.substr(c,32);
    }
    k=user_in.length()/32;
    for(int c = 0; c < k; c++) {
        final_val += decrypt_syb(new_input[c], key);
    }
    return final_val;
}

uint8_t GF256(uint8_t x, uint8_t y)
{
    /* Реализация побитовая маска для эффективного и безопасного
        криптографическое использование. */
    uint8_t p=0;
    for(int c=0;c<8;c++) {
        p ^= (uint8_t)(-(y&1)&x);
        x = (uint8_t)((x<<1) ^ (0x11b & -((x>>7)&1)));
        y >>= 1;
    }
    return p;
}

uint8_t** aes128::subBytes(uint8_t** b, uint8_t Nb)
{
    /* Разделяет шестнадцатеричный байт на 2 четверичных бита и использует
     * их в качестве индекса для подстановки значений
     * в качестве индекса s-box */
    for(int r=0;r<4;r++) {
        for(int c=0;c<Nb;c++) {
            uint8_t low_mask = b[r][c] & 0x0fU;
            uint8_t high_mask = b[r][c] >> 4;
            b[r][c] = sbox[high_mask][low_mask];
        }
    }
    return b;
}

uint8_t** shiftrows(uint8_t** state, uint8_t Nb)
{
   // Чтобы предотвратить переопределение значений, используется 2 массива с одинаковыми значениями
   uint8_t pre_state[4][Nb];
   for(int r=1;r<4;r++) {
       for(int c=0;c<Nb;c++)
           pre_state[r][c] = state[r][c];
   }
    // Операция ShiftRows. Первая строчка не изменена
    for(int r=1;r<4;r++) {
        for(int c=0;c<Nb;c++)
            state[r][c] = pre_state[r][(r+c)%4];
    }
    return state;
}

uint8_t** mixcolumns(uint8_t** state, uint8_t Nb)
{
    // лямбда-функция "xtime"
    auto xtime = [] (uint8_t x)
    {
        return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
    };

    for(int c=0;c<Nb;c++) {
        // создание временного массива чтобы остановить переопределение
        uint8_t tmpS[4] = {state[0][c], state[1][c], state[2][c],
                           state[3][c]};

        // Работа MixColumns по плану AES
        uint8_t tmp1 = (tmpS[0] ^ tmpS[1] ^ tmpS[2] ^ tmpS[3]);
        uint8_t tmp2 =  (tmpS[0] ^ tmpS[1]) ; tmp2 = xtime(tmp2);
        state[0][c] ^=  (tmp2 ^ tmp1);
        tmp2 =       (tmpS[1] ^ tmpS[2]) ; tmp2 = xtime(tmp2);
        state[1][c] ^=  (tmp2 ^ tmp1);
        tmp2 =       (tmpS[2] ^ tmpS[3]) ; tmp2 = xtime(tmp2);
        state[2][c] ^=  (tmp2 ^ tmp1);
        tmp2 =       (tmpS[3] ^ tmpS[0]) ; tmp2 = xtime(tmp2);
        state[3][c] ^=  (tmp2 ^ tmp1);
    }
    return state;
}

uint32_t aes128::sub_int(uint32_t y) {
    return sbox[(y&0xff)>>4][y&0x0fU];
}

uint32_t aes128::subword(uint32_t x)
{
    return (sub_int(x>>24)<<24) | (sub_int((x>>16)&0xff)<<16) |
           (sub_int((x>>8)&0xff)<<8) | (sub_int(x&0xff));
}

uint32_t aes128::rotword(uint32_t x) {return (x<<8)|((x>>32)-8);}

uint8_t** addroundkey(uint8_t** state, uint32_t* w, uint32_t rnd, uint8_t Nb)
{
    for(int c=0;c<Nb;c++) {
        uint32_t w_index = w[rnd*4+c];
        state[0][c] ^= (w_index >> 24) & 0xff;
        state[1][c] ^= (w_index >> 16) & 0xff;
        state[2][c] ^= (w_index >> 8) & 0xff;
        state[3][c] ^= w_index & 0xff;
    }
    return state;
}

uint32_t* aes128::keyExpansion(uint8_t* key, uint32_t* w, uint8_t Nb, uint8_t Nk, uint8_t Nr)
{
    uint32_t temp;
    int i=0;
    do {
        w[i] = ((uint32_t)key[4*i]<<24) | (key[4*i+1]<<16) |
               (key[4*i+2]<<8) | key[4*i+3];
        i++;
    } while(i<Nk);
    i=Nk;

    // Значения ркон. Двойная инициализация, чтобы он не переполнять
    uint32_t tmp_rcon[11];
    for(int c=1;c<11;c++) {
        tmp_rcon[c] = (uint8_t)(rcon[c] & 0xff)<<24;
    }

    while(i<Nb*(Nr+1)) {
        temp = w[i-1];
        if(i%Nk == 0) {
            temp = subword(rotword(temp)) ^ (uint32_t)tmp_rcon[i/Nk];
        }
        else if(Nk>6 && i%Nk == 4) {
            temp = subword(temp);
        }
        w[i] = temp ^ w[i-Nk];
        i++;
    }
    return w;
}

uint8_t* aes128::cipher(uint8_t* input, uint8_t* output, uint32_t* w,
                            uint8_t Nb, uint8_t Nr)
{
    // Объявления матрицы состояния
    uint8_t** state = nullptr;
    state = new uint8_t*[4];
    for(int r=0;r<4;r++) {
        state[r] = new uint8_t[Nb];
    }

    // Помещения значения одномерного массива в двумерную матрицу
    for(int r=0;r<4;r++) {
        for(int c=0;c<Nb;c++)
            state[r][c] = input[r+4*c];
    }

    // Функция вызова для управления матрицей состояния
    addroundkey(state, w, 0, Nb);
    for(int rnd=1;rnd<Nr;rnd++) {
        subBytes(state, Nb);
        shiftrows(state, Nb);
        mixcolumns(state, Nb);
        addroundkey(state, w, rnd, Nb);
    }
    subBytes(state, Nb);
    shiftrows(state, Nb);
    addroundkey(state, w, Nr, Nb);

    // Копирование массива состояний для вывода
    for(int r=0;r<4;r++) {
        for(int c=0;c<Nb;c++)
            output[r+4*c] = state[r][c];
    }
    for(int c=0;c<4;c++) {
       delete[] state[c];
    }
    delete[] state;
    return output;
}

std::string aes128::encrypt_syb(std::string user_in,uint8_t* key)
{
    // Объявление массивов
    uint8_t input[4*Nb];
    uint8_t output[4*Nb];
    uint32_t w[Nb*(Nr+1)]; // key schedule

    // Добавление пользовательского текста в одномерный массив
    for(int c=0;c<4*Nb;c++) {
        input[c] = user_in[c];
    }

    // Вызов функций KeyExpansion и Cipher
    keyExpansion(key, w, Nb, Nk, Nr);
    cipher(input, output, w, Nb, Nr);

    // Преобразование выходного массива в шестнадцатеричную строку
    std::stringstream ss;
    for (int c=0;c<4*Nb;c++)
    {
        ss << std::setw(2) << std::hex
           << (uint16_t)output[c];
    }
    return ss.str();
}

uint8_t** aes128::inv_subBytes(uint8_t** state, uint8_t Nb)
{
    for(int r=0;r<4;r++) {
        for(int c=0;c<Nb;c++) {
            uint8_t low_mask = state[r][c] & 0x0fU;
            uint8_t high_mask = state[r][c] >> 4;
            state[r][c] = inv_sbox[high_mask][low_mask];
        }
    }
    return state;
}

uint8_t** inv_shiftrows(uint8_t** state, uint8_t Nb)
{
    // Чтобы предотвратить переопределение значений, дублируется матрица
   uint8_t inv_pre_state[4][Nb];
   for(int r=1;r<4;r++) {
       for(int c=0;c<Nb;c++)
           inv_pre_state[r][c] = state[r][c];
   }


    // Сдвиг ряда. Первая строка не изменена
    for(int r=1;r<4;r++) {
        for(int c=0;c<Nb;c++)
            state[r][(r+c)%4] = inv_pre_state[r][c];
    }
    return state;
}

uint8_t** inv_mixcolumns(uint8_t** state, uint8_t Nb)
{
    uint8_t s_mixarr[4] = {0x0e, 0x0b, 0x0d, 0x09};
    for(int c=0;c<Nb;c++) {
        // Чтобы остановить переопределение матрицы, используйется временный массив
        uint8_t tmp_state[4] = {state[0][c], state[1][c], state[2][c],
                                state[3][c]};
        state[0][c] = (GF256(tmp_state[0], s_mixarr[0]) ^
                       GF256(tmp_state[1], s_mixarr[1]) ^
                       GF256(tmp_state[2], s_mixarr[2]) ^
                       GF256(tmp_state[3], s_mixarr[3]));
        state[1][c] = (GF256(tmp_state[0], s_mixarr[3]) ^
                       GF256(tmp_state[1], s_mixarr[0]) ^
                       GF256(tmp_state[2], s_mixarr[1]) ^
                       GF256(tmp_state[3], s_mixarr[2]));
        state[2][c] = (GF256(tmp_state[0], s_mixarr[2]) ^
                       GF256(tmp_state[1], s_mixarr[3]) ^
                       GF256(tmp_state[2], s_mixarr[0]) ^
                       GF256(tmp_state[3], s_mixarr[1]));
        state[3][c] = (GF256(tmp_state[0], s_mixarr[1]) ^
                       GF256(tmp_state[1], s_mixarr[2]) ^
                       GF256(tmp_state[2], s_mixarr[3]) ^
                       GF256(tmp_state[3], s_mixarr[0]));
    }
    return state;
}

uint8_t* aes128::invCipher(uint8_t* input, uint8_t* output, uint32_t* w,
                   uint8_t Nb, uint8_t Nr)
{
    // Объявление матрицы состояний как двумерный указатель
    uint8_t** state = nullptr;
    state = new uint8_t*[4];
    for(int r=0;r<4;r++) {
        state[r] = new uint8_t[Nb];
    }

    // Ввод во вторую матрицу
    for(int r=0;r<4;r++) {
        for(int c=0;c<Nb;c++)
            state[r][c] = input[r+4*c];
    }

    addroundkey(state, w, Nr, Nb);
    for(int rnd=Nr-1;rnd>0;rnd--) {
        inv_shiftrows(state, Nb);
        inv_subBytes(state, Nb);
        addroundkey(state, w, rnd, Nb);
        inv_mixcolumns(state, Nb);
    }

    inv_shiftrows(state, Nb);
    inv_subBytes(state, Nb);
    addroundkey(state, w, 0, Nb);

    // Вывод из второй матрицы
    for(int r=0;r<4;r++) {
        for(int c=0;c<Nb;c++)
            output[r+4*c] = state[r][c];
    }
    return output;
}

std::string aes128::decrypt_syb(std::string user_in, uint8_t* key)
{
    // Объявление одномерных массивов
    uint8_t output[4*Nb];
    uint8_t input[4*Nb];
    uint32_t w[Nb*(Nr+1)];
    std::stringstream conv;
    for (size_t c=0;c<user_in.length();c+=2) {
        conv << std::hex << user_in.substr(c,2);
        int32_t uint8;
        conv >> uint8;
        input[c/2] = uint8 & 0xffU;
        conv.str(std::string());
        conv.clear();
    }

    // Создание ключевого расширения и расшифровка
    keyExpansion(key, w, Nb, Nk, Nr);
    invCipher(input, output, w, Nb, Nr); // output wrong
    std::string str = "";
    // Вывод
    for(int c=0;c<4*Nb;c++) {
        str += output[c];
    }
    return str;
}

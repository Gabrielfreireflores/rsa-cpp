// Trabalho academico: criptografia RSA em C++.
// Equipe:
// Gabriel Freire Flôres - RA 2840482423010
// Marcelo Augusto Oliveira Jose - RA 2840482423043

#include <iostream>
#include <stdio.h>

// RSA didatico, sem padding: inadequado para proteger dados reais.
// Os limites mantem todos os calculos dentro de long long.
const long long LIMITE_PRIMO = 1000000000LL;

bool lerNumero(long long &numero, long long limite) {
    char linha[128];
    if (!std::cin.getline(linha, 128)) return false;
    numero = 0;
    int i = 0;
    while (linha[i] == ' ' || linha[i] == '\t') ++i;
    bool temDigito = false;
    while (linha[i] >= '0' && linha[i] <= '9') {
        int digito = linha[i++] - '0';
        if (numero > (limite - digito) / 10) return false;
        numero = numero * 10 + digito;
        temDigito = true;
    }
    while (linha[i] == ' ' || linha[i] == '\t') ++i;
    return temDigito && linha[i] == '\0' && numero <= limite;
}

bool primo(long long numero) {
    if (numero < 2) return false;
    if (numero % 2 == 0) return numero == 2;
    // divisor <= numero/divisor equivale a divisor*divisor <= numero.
    for (long long divisor = 3; divisor <= numero / divisor; divisor += 2)
        if (numero % divisor == 0) return false;
    return true;
}

long long mdc(long long a, long long b) {
    while (b != 0) {
        long long resto = a % b;
        a = b;
        b = resto;
    }
    return a;
}

long long inversoModular(long long e, long long modulo) {
    // Euclides estendido: acompanha o coeficiente de e na identidade de Bezout.
    long long r = modulo, novoR = e;
    long long t = 0, novoT = 1;
    while (novoR != 0) {
        long long quociente = r / novoR;
        long long proximoR = r - quociente * novoR;
        long long proximoT = t - quociente * novoT;
        r = novoR;
        novoR = proximoR;
        t = novoT;
        novoT = proximoT;
    }
    if (r != 1) return -1;
    if (t < 0) t += modulo;
    return t;
}

long long somarModulo(long long a, long long b, long long modulo) {
    // a e b estao em [0, modulo): evita calcular uma soma que possa transbordar.
    return a >= modulo - b ? a - (modulo - b) : a + b;
}

long long multiplicarModulo(long long a, long long b, long long modulo) {
    long long resultado = 0;
    while (b > 0) {
        if (b % 2 == 1) resultado = somarModulo(resultado, a, modulo);
        a = somarModulo(a, a, modulo);
        b /= 2;
    }
    return resultado;
}

long long potenciaModulo(long long base, long long expoente, long long modulo) {
    long long resultado = 1;
    base %= modulo;
    // Exponenciacao binaria: usa os bits do expoente e quadrados sucessivos.
    while (expoente > 0) {
        if (expoente % 2 == 1)
            resultado = multiplicarModulo(resultado, base, modulo);
        base = multiplicarModulo(base, base, modulo);
        expoente /= 2;
    }
    return resultado;
}

int main() {
    printf("RSA didatico, sem padding. Nao use para proteger dados reais.\n");
    long long p, q;
    printf("Digite p (primo, ate 1000000000): ");
    if (!lerNumero(p, LIMITE_PRIMO)) {
        fprintf(stderr, "Erro: p deve ser um inteiro entre 0 e 1000000000.\n");
        return 1;
    }
    // Bloqueia a geracao das chaves se p nao for primo.
    if (!primo(p)) {
        fprintf(stderr, "Erro: p nao e primo. Operacao bloqueada.\n");
        return 1;
    }
    printf("Digite q (primo distinto, ate 1000000000): ");
    if (!lerNumero(q, LIMITE_PRIMO)) {
        fprintf(stderr, "Erro: q deve ser um inteiro entre 0 e 1000000000.\n");
        return 1;
    }
    // Bloqueia a geracao das chaves se q nao for primo.
    if (!primo(q)) {
        fprintf(stderr, "Erro: q nao e primo. Operacao bloqueada.\n");
        return 1;
    }
    if (p == q) {
        fprintf(stderr, "Erro: p e q devem ser primos distintos.\n");
        return 1;
    }
    long long n = p * q;
    long long phi = (p - 1) * (q - 1);
    // n > 127 permite representar qualquer byte ASCII aceito pelo programa.
    if (n <= 127) {
        fprintf(stderr, "Erro: escolha primos cujo produto seja maior que 127.\n");
        return 1;
    }
    long long e = 2;
    while (e < phi && mdc(e, phi) != 1) ++e;
    long long d = inversoModular(e, phi);
    if (e >= phi || d < 1) {
        fprintf(stderr, "Erro: nao foi possivel gerar as chaves.\n");
        return 1;
    }
    std::cout << "Chave publica (e, n): (" << e << ", " << n << ")\n";
    std::cout << "Chave privada (d, n): (" << d << ", " << n << ")\n";
    char mensagem[1024];
    printf("Digite o texto ASCII (uma linha, ate 1023 caracteres): ");
    if (!std::cin.getline(mensagem, 1024)) {
        fprintf(stderr, "Erro: texto ausente ou maior que o limite.\n");
        return 1;
    }
    for (int i = 0; mensagem[i] != '\0'; ++i) {
        unsigned char caractere = static_cast<unsigned char>(mensagem[i]);
        if (caractere > 127) {
            fprintf(stderr, "Erro: utilize somente caracteres ASCII, sem acentos.\n");
            return 1;
        }
    }
    printf("Numeros criptografados:\n");
    for (int i = 0; mensagem[i] != '\0'; ++i) {
        if (i != 0) std::cout << ' ';
        std::cout << potenciaModulo(static_cast<unsigned char>(mensagem[i]), e, n);
    }
    std::cout << '\n';
    return 0;
}

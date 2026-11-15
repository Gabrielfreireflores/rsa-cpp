// Trabalho academico: criptografia RSA em C++.
// Equipe:
// Gabriel Freire Flôres - RA 2840482423010
// Marcelo Augusto Oliveira Jose - RA 2840482423043

#include <iostream>
#include <stdio.h>

// RSA didatico, sem padding: inadequado para proteger dados reais.
const long long LIMITE = 1000000000000000000LL;

bool lerNumero(long long &numero) {
    char linha[128];
    if (!std::cin.getline(linha, 128)) return false;
    numero = 0;
    int i = 0;
    while (linha[i] == ' ' || linha[i] == '\t') ++i;
    bool temDigito = false;
    while (linha[i] >= '0' && linha[i] <= '9') {
        int digito = linha[i++] - '0';
        if (numero > (LIMITE - digito) / 10) return false;
        numero = numero * 10 + digito;
        temDigito = true;
    }
    while (linha[i] == ' ' || linha[i] == '\t') ++i;
    return temDigito && linha[i] == '\0' && numero <= LIMITE;
}

long long somarModulo(long long a, long long b, long long modulo) {
    return a >= modulo - b ? a - (modulo - b) : a + b;
}

long long multiplicarModulo(long long a, long long b, long long modulo) {
    // Soma e duplicacao modular evitam calcular diretamente a*b.
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
    // Exponenciacao binaria, com reducao modular em cada multiplicacao.
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
    long long d, n;
    printf("Digite d da chave privada: ");
    if (!lerNumero(d) || d < 1) {
        fprintf(stderr, "Erro: d deve ser positivo e no maximo 10^18.\n");
        return 1;
    }
    printf("Digite n da chave privada: ");
    if (!lerNumero(n) || n <= 127 || d >= n) {
        fprintf(stderr, "Erro: n deve estar entre 128 e 10^18, com d < n.\n");
        return 1;
    }
    char linha[32768];
    char mensagem[1024];
    int tamanho = 0;
    printf("Cole os numeros criptografados em uma linha, separados por espacos:\n");
    if (!std::cin.getline(linha, 32768)) {
        fprintf(stderr, "Erro: linha ausente ou maior que o limite.\n");
        return 1;
    }
    int i = 0;
    while (true) {
        while (linha[i] == ' ' || linha[i] == '\t') ++i;
        if (linha[i] == '\0') break;
        if (linha[i] < '0' || linha[i] > '9' || tamanho >= 1023) {
            fprintf(stderr, "Erro: numeros invalidos ou mais de 1023 caracteres.\n");
            return 1;
        }
        long long cifrado = 0;
        while (linha[i] >= '0' && linha[i] <= '9') {
            int digito = linha[i++] - '0';
            if (cifrado > (LIMITE - digito) / 10) {
                fprintf(stderr, "Erro: numero criptografado excede o limite.\n");
                return 1;
            }
            cifrado = cifrado * 10 + digito;
        }
        if ((linha[i] != '\0' && linha[i] != ' ' && linha[i] != '\t') || cifrado >= n) {
            fprintf(stderr, "Erro: cada numero deve estar entre 0 e n-1, separado por espacos.\n");
            return 1;
        }
        long long original = potenciaModulo(cifrado, d, n);
        if (original < 1 || original > 127) {
            fprintf(stderr, "Erro: resultado fora do texto ASCII aceito; confira a chave e os numeros.\n");
            return 1;
        }
        mensagem[tamanho++] = static_cast<char>(original);
    }
    mensagem[tamanho] = '\0';
    // Uma chave incorreta pode produzir ASCII valido; RSA puro nao autentica dados.
    std::cout << "Mensagem original: " << mensagem << '\n';
    return 0;
}

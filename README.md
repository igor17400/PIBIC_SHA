# Projeto de pesquisa utilizando algoritmos Hash e FPGA

## Introdução

Elaboração de um projeto de pesquisa em conjunto com o professor Alexandre Solon Nery (alexandre.nery@redes.unb.br). <br/>
O objetivo do projeto é atestar a eficiência de se utilizar FPGA para proteção de sistemas computacionais. 
<br/>
A primeira parte do projeto consiste em comparar algoritmos de hash do tipo SHA256 e SHA3, sendo processados no FPGA e demonstrar qual hash é mais seguro. E a segunda parte do projeto consiste em comprovar a eficiência da FPGA para segurança.

## Motivação

O texto a seguir tem como objetivo auxiliar todos as aqueles que desejam pesquisar ou estudar sobre a área de criptografia. Ao desenvolver o projeto tive algumas dificuldades e por isso estou compartilhando os meus resultados para que os próximos consigam ter mais referências, principalmente em português, visto que a maioria dos exemplos e explicações são em Inglês.
Todas as citações e utilizações de códigos terão as suas devidas referências e créditos. Não sou um expert em segurança, muito menos em algoritmos, posso acabar fazendo algumas citações ou explicações erradas. Posso também ter cometido erros de portguês conforme escrevi o texto. Qualquer crítica, questionamento, dúvida ou até mesmo ajuda por favor enviar um email em igorlima1740@gmail.com. 
<br>
<br>
Espero que ajude :)

## Secure Hash Algorithm - SHA

Faz parte do conjunto de várias funções de criptografia utilizadas para manter dados seguros. Ao receber uma entrada de texto, essa função realizará operações para gerar uma sequência de números de tamanho único independente do tamanho da entrada, message digest. O link (http://www.sha1-online.com/) demonstra exatamente isso utilizando o algoritmo SHA1, ao colocar qualquer texto de entrada obtemos uma saída única, como por exemplo:

"ola"--> 793f970c52ded1276b9264c742f19d1888cbaf73 (resultado da conversão)

Essa é uma breve introdução do que é o SHA, podemos checar outros links como referência:

- https://brilliant.org/wiki/secure-hashing-algorithms/#sha-characteristics

- https://en.wikipedia.org/wiki/Secure_Hash_Algorithms

- https://csrc.nist.gov/Projects/Hash-Functions/NIST-Policy-on-Hash-Functions

- https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf


## SHA256 VS SHA3

O dois são modelos de secure hash functions. Vamos explicar cada um deles e depois apontar as suas diferenças e porque um está depreciado e porque o outro é o futuro dos SHAs.

### SHA256

O SHA256 faz parte da segunda versão dos SHAs regulada pela NIST (National Institute of Standards and Technology). Mas, porque o 256? O SHA deve processar uma mensagem e retornar como resposta um número com contéudo dependende da entrada e com tamanho único. O 256 representa exatamente o tamanho de saída do hash, que no caso são 256 bits. Temos também SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 e SHA-512/256.

Para explicar o SHA256 vamos utilizar duas páginas, uma teórica e uma prática:

- https://www.cs.rit.edu/~ark/lectures/onewayhash/onewayhash.shtml (teórica / <mark>imagens</mark>), Alan Kaminsky
- https://github.com/B-Con/crypto-algorithms (prática), Brad Conte (brad@bradconte.com)

Quando alguma referência a código for feita, estaremos utilizando o excelente trabalho feito por Brad Conte.

Primeiramente, vamos começar pelo SHA256.h

```
typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;
```

Aqui temos a definição de um contexto no qual teremos alguns dados muitos importantes. Como explicado antes o SHA256 dá como resposta um texto de 256 bits, ou 64 bytes, como podemos ver no tipo BYTE data[64]. Os tipos BYTE e WORD são definidos mais acima no código, a ideia como o código já comenta BYTE, é definido como 8 bits e WORD é definido para ser uma palavra de 32 bits, visto que todas operações realizadas no processo de obtenção do hash são feitas em palavras de 32 bits. Os outros tipos serão explicados mais adiante.

Temos definido três funções, 

```
/*********************** FUNCTION DECLARATIONS **********************/

void sha256_init(SHA256_CTX *ctx);
/* Descrição da função: essa função é utilizada para inicializar cada variável do nosso registro SHA256_CTX. */

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
/*Descrição da função: essa função é utilizada para aplicar a SHA-256 compression function a cada bloco do BYTE data[].*/

void sha256_final(SHA256_CTX *ctx, BYTE hash[]);
/*Descrição da função: essa função nos da o resultado final do sha256-hash do BYTE hash[] */
```

Para entender melhor as funções presentes no arquivo sha256.c podemos consultar a seguinte tabela que descreve as características do SHA256.

```
----------------------------------------------------
Descrição geral do SHA256:                          |
                                    SHA-256         |
 Message size                       < 2^64          |
 Word size                          32              |
 Block size                         512             |
 Message digest size                256             |
 Number of steps                    64              |
 Security                           128             |
 ---------------------------------------------------
 ```

Temos no código as funções chamadas Little Functions as quais serão utilizadas na função ```sha256_transform```

```
/*--------------- THE LITTLE FUNCTIONS --------------
 
Aqui temos as definições de algumas funções que utilizaremos durante todo o processo da conversão de uma mensagem em um hash */

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
/* Ch --> choose */
/* Ch(X,Y,Z) = (X and Y) xor ((not X) and Z) */

#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
/* Maj --> majority */
/* Maj(X,Y,Z) = (X and Y) xor (X and Z) xor (Y and Z) */

#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
/* Σ0(X) = (X right-rotate 2) xor (X right-rotate 13) xor (X right-rotate 22) */

#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
/* Σ1(X) = (X right-rotate 6) xor (X right-rotate 11) xor (X right-rotate 25) */

#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
/* σ0(X) = (X right-rotate 7) xor (X right-rotate 18) xor (X right-shift 3) */

#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
/* σ1(X) = (X right-rotate 17) xor (X right-rotate 19) xor (X right-shift 10) */
```
Para obter o hash, temos que seguir a seguinte ordem

1) criamos um contexto, ```SHA256_CTX ctx```;
2) criamos a string a ser convertida, ```BYTE text_um[] = {"abc"};```
3) inicializamos o buf, ```BYTE buf[SHA256_BLOCK_SIZE]```;
4) ```sha256_init(&ctx)```;
5) ```sha256_update(&ctx, text_um, strlen(text_um));```
6) ```sha256_final(&ctx, buf);```
7) opcional para visualizar o hash, ```printf("%02x ", buf[i]);```


#### Começando pela função primeira função chamada, ```sha256_init```:

A ideia da função é inicializar os valores ```datalen```, ```bitlen``` e  ```state[8]``` do nosso contexto.

As constantes definidas são bem explicadas pela seguinte citação do artigo, "The initial hash value H(0) is the following sequence of 32-bit words (which are
obtained by taking the fractional parts of the square roots of the first eight primes: 2, 3, 5, 7, 11, 13, 17, and 19)" - <mark>tradução</mark> - "O valor inicial do hash H (0) é a seguinte sequência de palavras de 32 bits (que são
obtido tomando as partes fracionárias das raízes quadradas dos oito primeiros números primos: 2, 3, 5, 7, 11, 13, 17 e 19)"

referência: http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf

```
void sha256_init(SHA256_CTX *ctx){
    ctx->datalen = 0;
    ctx->bitlen = 0;

    ctx->state[0] = 0x6a09e667; /* 2 */
    ctx->state[1] = 0xbb67ae85; /* 3 */
    ctx->state[2] = 0x3c6ef372; /* 5 */
    ctx->state[3] = 0xa54ff53a; /* 7 */
    ctx->state[4] = 0x510e527f; /* 11 */
    ctx->state[5] = 0x9b05688c; /* 13 */
    ctx->state[6] = 0x1f83d9ab; /* 17 */
    ctx->state[7] = 0x5be0cd19; /* 19 */
}
```

#### Segunda função, ```sha256_update```:

Como podemos ver no diagrama:
![](/images/SHA256Fig3.png)

A nossa função ```sha256_update``` chama a função ```sha256_transform```(round function, no diagrama) a cada rodada. A qual altera a nossa variável ```ctx->state``` aplicando as funções - little functions - apresentadas acima. 


#### Terceira função, ```sha256_final```:

Vamos salvar na variável ```hash[]``` o resultado de todo o processamento, após mais algumas chamadas da função ```sha256_transform```.

Vale destacar o comentário do código:

```
// Since this implementation uses little endian byte ordering and SHA uses big endian,
// reverse all the bytes when copying the final state to the output hash.
```

É preciso reverter a ordem do hash final de little endian para big endian. 

- dúvidas sobre litte endian e big endian: https://pt.wikipedia.org/wiki/Extremidade_(ordena%C3%A7%C3%A3o)

Por fim, utilizando o código obtemos:
```
Hash resultante de abc: 
c5 e6 81 84 d2 86 95 73 fe ba b8 88 fe 67 35 5a f2 6a 5f c0 59 a5 0f 8d 33 2e fe 10 5b d9 40 4a 
```

### SHA 3













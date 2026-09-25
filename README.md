# 💻 Chat E2EE — Aplicação Cliente (`clienteRedes`)

[![Python 3](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![GUI](https://img.shields.io/badge/GUI-Tkinter-blue.svg)]()
[![Security](https://img.shields.io/badge/Security-E2EE%20%7C%20AES--256%20%7C%20HMAC-green.svg)]()
[![License](https://img.shields.io/badge/License-Academic-orange.svg)]()

> **Aplicação Cliente Desktop com Interface Gráfica e Criptografia Ponta a Ponta (E2EE)**  
> *Desenvolvida para a disciplina de Segurança da Informação / Redes de Computadores (Engenharia de Computação — UABJ/UFRPE)*  
> *Professor: Ygor Amaral B. L. de Sena*

---

## 📋 Sumário
- [Visão Geral](#-visão-geral)
- [Garantias de Privacidade e Segurança](#-garantias-de-privacidade-e-segurança)
- [Funcionalidades Principais](#-funcionalidades-principais)
- [Arquitetura em Camadas](#-arquitetura-em-camadas)
- [O Chaveiro do Cliente e Gestão de Chaves](#-o-chaveiro-do-cliente-e-gestão-de-chaves)
- [Fluxo de Dupla Camada de Cifragem](#-fluxo-de-dupla-camada-de-cifragem)
- [Estrutura do Repositório](#-estrutura-do-repositório)
- [Como Executar](#-como-executar)
- [Autor](#-autor)

---

## 📄 Visão Geral

O **`clienteRedes`** é a aplicação desktop que fornece a interface gráfica do chat para o usuário final. Desenvolvido em **Python 3** utilizando **Tkinter** para a GUI e **Sockets TCP** para comunicação de rede, o cliente combina usabilidade em tempo real com mecanismos avançados de **criptografia ponta a ponta (E2EE)**.

Todas as mensagens são cifradas localmente na máquina do cliente antes de trafegarem pela rede. Assim, nem mesmo o servidor de roteamento tem capacidade técnica para visualizar o conteúdo das conversas.

---

## 🛡️ Garantias de Privacidade e Segurança

* **Confidencialidade Ponta a Ponta (E2EE)**: As mensagens trocadas entre dois usuários são cifradas com **AES-256** utilizando chaves de sessão exclusivas negociadas diretamente entre os dois clientes.
* **Integridade e Autenticidade (*Encrypt-then-MAC*)**: Cada pacote inclui um **HMAC-SHA-256**. O cliente receptor valida obrigatoriamente o HMAC antes de tentar decifrar o conteúdo, descartando mensagens adulteradas.
* **Autenticação Mútua Cruzada**: Após o handshake E2EE entre dois contatos, ambos realizam um desafio mútua com *nonces* assinados digitalmente (**RSA-PSS** ou **Ed25519**) para confirmar suas identidades.
* **Proteção de Histórico Local**: O histórico de bate-papo gravado em disco é cifrado localmente com **AES-256** e uma chave exclusiva da máquina do usuário.
* **Alerta de Segurança para Contatos Offline**: Se o destinatário estiver offline e não houver uma chave E2EE previamente negociada entre a dupla, a aplicação bloqueia o envio e alerta o usuário na interface.

---

## 🚀 Funcionalidades Principais

* **Interface Gráfica Amigável (Tkinter)**:
  * Tela de Login e Registro de novo usuário.
  * Painel principal com lista de contatos e status online/offline em tempo real.
  * Janela de conversa com histórico e indicador de *"Digitando"*.
* **Concorrência Assíncrona via Threads**:
  * Thread principal dedicada à execução da interface gráfica (GUI).
  * Thread secundária (`receive_messages`) dedicada à escuta contínua do socket TCP sem travar a tela.
* **Handshake E2EE Automático**:
  * Negociação transparente de chaves simétricas de sessão DHE + HKDF (SHA-256) ao iniciar conversas com contatos.
* **Autenticação de Dispositivo Conhecido**:
  * Login automático sem senha via resposta a desafio (*nonce*) do servidor assinado com a chave privada local.
* **Histórico Cifrado**:
  * Carregamento e salvamento automático das conversas cifradas no disco local.

---

## 🏗️ Arquitetura em Camadas

A arquitetura do cliente organiza-se em quatro níveis principais, mantendo a interface gráfica desacoplada dos algoritmos de criptografia e dos sockets de rede:

```
                  +-------------------------------------------------------+
                  |                     APRESENTAÇÃO                      |
                  |  Interface Gráfica Tkinter: Login, Contatos, Chat GUI |
                  +-------------------------------------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |                       DOMÍNIO                         |
                  |  Serviço: Sessão do Usuário, Conversas, Presença      |
                  +-------------------------------------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |                      SEGURANÇA                        |
                  |  • Política & Sessão: Chaveiro Duplo, Handshake E2EE, |
                  |    Autenticação Mútua, Expiração de Chaves            |
                  |  • Mecanismo (Primitivas): AES-256, HMAC, HKDF,       |
                  |    DHE, RSA-PSS / Ed25519                             |
                  +-------------------------------------------------------+
                                              |
                                              v
                  +-------------------------------------------------------+
                  |                    INFRAESTRUTURA                     |
                  |  • Rede & Protocolo: Socket TCP & Thread de Recepção  |
                  |  • Persistência: Histórico de Chat Cifrado em Disco   |
                  +-------------------------------------------------------+
```

---

## 🔑 O Chaveiro do Cliente e Gestão de Chaves

A camada de segurança do cliente gerencia dois conjuntos distintos de chaves em memória, evitando confusão entre a segurança do canal e a privacidade ponta a ponta:

1. **Chaves do Canal com o Servidor**:
   * Utilizadas para proteger a trafegabilidade socket até o servidor (AES-256 Chave 1 + HMAC Chave 2).
   * Renovadas a cada 60 minutos ou 100 mensagens.
2. **Chaves de Sessão E2EE (Por Contato)**:
   * Mantidas em um dicionário em memória contendo o par de chaves simétricas (AES-256 + HMAC) para cada contato com quem o usuário manteve handshake.
3. **Par de Chaves Assimétricas (RSA / ECC)**:
   * Chave privada mantida em segredo no cliente para assinar desafios de login e autenticação mútua.
   * Chave pública enviada ao servidor para verificação pelos pares.
4. **Chave do Histórico Local**:
   * Chave simétrica usada para cifrar os arquivos de histórico no disco.

---

## 📦 Fluxo de Dupla Camada de Cifragem

Ao enviar uma mensagem para outro usuário, o cliente aplica o envelopamento em dupla camada:

```
[ Texto da Mensagem ]
        |
        v  (Cifrado com Chaves E2EE do Destinatário)
[ Camada Interna E2EE: AES-256 + HMAC-SHA-256 ]
        |
        v  (Cifrado com Chaves do Canal do Servidor)
[ Camada Externa do Canal: AES-256 + HMAC-SHA-256 ]
        |
        v
 (Enviado via Socket TCP)
```

No destino, o processo é invertido: o receptor valida o HMAC da camada externa, decifra o canal, depois valida o HMAC da camada interna e decifra o miolo E2EE para exibição no Tkinter.

---

## 📂 Estrutura do Repositório

```
clienteRedes/
├── cliente.py             # Script principal (Interface Tkinter, Threads, Handshakes e Sockets)
├── README.md              # Documentação oficial da aplicação
└── requirements.txt       # Dependências de bibliotecas Python
```

---

## ⚡ Como Executar

### **Pré-requisitos**
* Python **3.10+** instalado.
* O **`servidorRedes`** deve estar em execução na rede local ou máquina host.
* Dependências criptográficas (`cryptography` ou `pycryptodome`).

### **Passos:**

1. **Clonar o repositório:**
   ```bash
   git clone https://github.com/oVictorTorres/clienteRedes.git
   cd clienteRedes
   ```

2. **Instalar as dependências:**
   ```bash
   pip install cryptography
   ```

3. **Iniciar a Aplicação Cliente:**
   ```bash
   python cliente.py
   ```

4. **Simulando Múltiplos Usuários:**
   Para testar a conversa entre dois ou mais usuários na mesma máquina, abra múltiplos terminais e execute `python cliente.py` em cada um deles, registrando ou autenticando contas diferentes (ex: `alice` e `bob`).

---

## 👤 Autor
* **João Ricardo & Vinicius Lira** (Desenvolvimento & Arquitetura)  
* **Disciplina**: Segurança da Informação / Redes de Computadores — UABJ/UFRPE

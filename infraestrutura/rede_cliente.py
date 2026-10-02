import socket
import threading

from seguranca.sessao_canal import SessaoCanalCliente

HOST_PADRAO = "127.0.0.1"
PORTA_PADRAO = 5000


class RedeCliente:
    def __init__(self, host=HOST_PADRAO, port=PORTA_PADRAO):
        self.host = host
        self.port = port
        self.socket = None
        self.conectado = False
        self.thread_escuta = None
        self.callback_pacote = None
        self.sessao = None

    def conectar(self, host=None, port=None) -> bool:
        """Abre a conexão TCP e tenta o handshake DHE do canal.

        Se o servidor não suportar o handshake, segue em texto puro
        (compatibilidade retroativa).
        """
        if host:
            self.host = host
        if port:
            self.port = port

        if self.conectado and self.socket:
            return True

        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.conectado = True
        except socket.error as e:
            print(f"[REDE] Falha ao conectar: {e}")
            self.conectado = False
            self.socket = None
            return False

        # ---- Tentativa de handshake (opcional) ----
        self.sessao = SessaoCanalCliente()
        try:
            init = self.sessao.gerar_handshake_init()
            self.socket.sendall(init.encode("utf-8"))
            self.socket.settimeout(5)
            resp_bruta = self.socket.recv(4096)
            self.socket.settimeout(None)

            if resp_bruta:
                resp_str = resp_bruta.decode("utf-8", errors="ignore")
                if resp_str.startswith("HANDSHAKE_RESP"):
                    if self.sessao.processar_handshake_resp(resp_str):
                        print("[HANDSHAKE] Canal cifrado estabelecido.")
                    else:
                        print(
                            "[HANDSHAKE] Resposta inválida — "
                            "seguindo sem canal."
                        )
                        self.sessao = None
                else:
                    print(
                        "[HANDSHAKE] Servidor não suporta handshake "
                        f"(resposta: {resp_str[:60]!r}) — "
                        "seguindo sem canal."
                    )
                    self.sessao = None
            else:
                print("[HANDSHAKE] Sem resposta — seguindo sem canal.")
                self.sessao = None
        except socket.timeout:
            self.socket.settimeout(None)
            print("[HANDSHAKE] Timeout — seguindo sem canal.")
            self.sessao = None
        except socket.error as e:
            print(f"[HANDSHAKE] Erro de socket: {e} — seguindo sem canal.")
            self.sessao = None

        return True

    def enviar_e_receber(self, mensagem, timeout=5) -> tuple[bool, str]:
        """Envia uma mensagem síncrona e aguarda a resposta imediata.

        Usado durante a fase inicial de login/registro.
        Cifra se o canal estiver ativo.
        """
        if not self.conectado or not self.socket:
            return False, "Socket não conectado."

        try:
            dados_str = (
                mensagem if isinstance(mensagem, str) else mensagem.decode()
            )
            if self.sessao and self.sessao.canal_ativo:
                dados_str = self.sessao.cifrar_saida(dados_str)

            self.socket.sendall(dados_str.encode("utf-8"))

            self.socket.settimeout(timeout)
            resposta_bruta = self.socket.recv(65536)
            self.socket.settimeout(None)  # Restaura o modo bloqueante normal

            if not resposta_bruta:
                return False, "Conexão encerrada pelo servidor."

            resposta_str = resposta_bruta.decode("utf-8", errors="ignore")
            if self.sessao and self.sessao.canal_ativo:
                resposta_str = self.sessao.decifrar_entrada(resposta_str)
                if not resposta_str:
                    return False, "Falha ao decifrar a resposta."

            return True, resposta_str
        except socket.timeout:
            self.socket.settimeout(None)
            return False, "Tempo de resposta do servidor esgotado (timeout)."
        except socket.error as e:
            return False, f"Erro de comunicação no socket: {e}"

    def enviar_comando(self, comando) -> bool:
        """Envia bytes ou strings pelo socket ativo (cifrado se ativo)."""
        if not self.conectado or not self.socket:
            return False

        try:
            dados_str = (
                comando if isinstance(comando, str) else comando.decode()
            )
            if self.sessao and self.sessao.canal_ativo:
                dados_str = self.sessao.cifrar_saida(dados_str)

            self.socket.sendall(dados_str.encode("utf-8"))
            return True
        except socket.error:
            self.desconectar()
            return False

    def iniciar_escuta(self, callback_processar_pacote):
        """Inicia thread em segundo plano para escuta contínua de pacotes."""
        self.callback_pacote = callback_processar_pacote
        self.thread_escuta = threading.Thread(
            target=self._loop_recepcao, daemon=True
        )
        self.thread_escuta.start()

    def _loop_recepcao(self):
        """Loop em segundo plano: recebe, decifra o canal e repassa."""
        while self.conectado and self.socket:
            try:
                dados = self.socket.recv(65536)
                if not dados:
                    break

                texto = dados.decode("utf-8", errors="ignore")
                if self.sessao and self.sessao.canal_ativo:
                    texto = self.sessao.decifrar_entrada(texto)

                if texto and self.callback_pacote:
                    self.callback_pacote(texto)

            except socket.error:
                break

        self.desconectar()

    def desconectar(self):
        """Encerra graciosamente a conexão socket TCP."""
        self.conectado = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.socket.close()
            except Exception:
                pass
            self.socket = None
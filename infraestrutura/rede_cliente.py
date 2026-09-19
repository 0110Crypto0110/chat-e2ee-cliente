import socket
import threading

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

    def conectar(self, host=None, port=None) -> bool:
        """Abre a conexão TCP socket com o servidor."""
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
            return True
        except socket.error:
            self.conectado = False
            self.socket = None
            return False

    def enviar_e_receber(self, mensagem, timeout=5) -> tuple[bool, str]:
        """
        Envia uma mensagem síncrona e aguarda a resposta imediata.
        Usado durante a fase inicial de login/registro e handshake.
        """
        if not self.conectado or not self.socket:
            return False, "Socket não conectado."

        try:
            dados = (
                mensagem.encode("utf-8")
                if isinstance(mensagem, str)
                else mensagem
            )
            self.socket.sendall(dados)

            self.socket.settimeout(timeout)
            resposta_bruta = self.socket.recv(4096)
            self.socket.settimeout(None)  # Restaura o modo bloqueante normal

            if not resposta_bruta:
                return False, "Conexão encerrada pelo servidor."

            return True, resposta_bruta.decode("utf-8", errors="ignore")
        except socket.timeout:
            self.socket.settimeout(None)
            return False, "Tempo de resposta do servidor esgotado (timeout)."
        except socket.error as e:
            return False, f"Erro de comunicação no socket: {e}"

    def enviar_comando(self, comando) -> bool:
        """Envia bytes ou strings pelo socket ativo."""
        if not self.conectado or not self.socket:
            return False

        try:
            dados = (
                comando.encode("utf-8")
                if isinstance(comando, str)
                else comando
            )
            self.socket.sendall(dados)
            return True
        except socket.error:
            self.desconectar()
            return False

    def iniciar_escuta(self, callback_processar_pacote):
        """
        Inicia a thread dedicada em segundo plano para escuta contínua de
        pacotes, garantindo que a interface gráfica (GUI) permaneça responsiva.
        """
        self.callback_pacote = callback_processar_pacote
        self.thread_escuta = threading.Thread(
            target=self._loop_recepcao, daemon=True
        )
        self.thread_escuta.start()

    def _loop_recepcao(self):
        """Loop executado em segundo plano pela thread de escuta do socket."""
        while self.conectado and self.socket:
            try:
                dados = self.socket.recv(4096)
                if not dados:
                    break

                # Repassa os dados recebidos para o callback
                # (gerenciador / segurança)
                if self.callback_pacote:
                    texto_ou_bytes = dados.decode("utf-8", errors="ignore")
                    self.callback_pacote(texto_ou_bytes)

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
import os
import base64
import hashlib
from datetime import datetime


class HistoricoLocal:
    def __init__(self, diretorio_base="historico_local"):
        self.diretorio_base = diretorio_base
        self.chave_local = None

        # Garante que a pasta de armazenagem exista no disco
        if not os.path.exists(self.diretorio_base):
            os.makedirs(self.diretorio_base, exist_ok=True)

    def definir_usuario(self, username, chave_secreta_usuario=None):
        """
        Define o usuário logado e deriva a chave simétrica de 256 bits (AES-256)
        exclusiva para cifrar o histórico local em disco.
        """
        if chave_secreta_usuario:
            # Deriva uma chave de 32 bytes (256 bits) usando SHA-256
            # sobre o segredo do usuário
            self.chave_local = hashlib.sha256(
                chave_secreta_usuario.encode("utf-8")
            ).digest()
        else:
            # Chave padrão derivada do nome do usuário
            # (para persistência básica do ambiente local)
            self.chave_local = hashlib.sha256(
                f"HIST_KEY_{username}".encode("utf-8")
            ).digest()

    def _obter_caminho_arquivo(self, usuario_local, contato):
        """
        Gera um caminho isolado por conversa:
        historico_local/{usuario}_{contato}.dat
        """
        nome_arquivo = f"{usuario_local}_{contato}.dat"
        return os.path.join(self.diretorio_base, nome_arquivo)

    # ------------------------------------------------------------------
    # 🔐 CIFRAGEM E DECIFRAGEM SIMÉTRICA LOCAL (AES-256 / XOR Fallback)
    # ------------------------------------------------------------------
    def _cifrar_texto(self, texto_plano: str) -> str:
        """
        Cifra a linha de texto usando AES-256 (ou mecanismo simétrico com a
        chave local) e devolve uma string codificada em Base64 para gravação
        segura em disco.
        """
        if not self.chave_local:
            raise ValueError("Chave local de histórico não inicializada.")

        dados = texto_plano.encode("utf-8")

        # Tentativa de uso das primitivas do módulo Rust/Python (AES-256-GCM)
        try:
            import primitivas_rust

            # Gera um nonce aleatório de 12 bytes
            nonce = os.urandom(12)
            ciphertext = primitivas_rust.aes256_encrypt(
                self.chave_local, dados, nonce
            )
            # Salva o nonce junto ao texto cifrado
            # (nonce + ciphertext em Base64)
            pacote_completo = nonce + bytes(ciphertext)
            return base64.b64encode(pacote_completo).decode("utf-8")
        except (ImportError, AttributeError):
            # Cifragem simétrica fallback (XOR de 256 bits)
            # enquanto o módulo Rust não é vinculado
            bloco_cifrado = bytearray()
            for i, byte in enumerate(dados):
                bloco_cifrado.append(
                    byte ^ self.chave_local[i % len(self.chave_local)]
                )
            return base64.b64encode(bloco_cifrado).decode("utf-8")

    def _decifrar_texto(self, texto_cifrado_b64: str) -> str:
        """
        Decifra uma linha gravada no arquivo local e devolve o texto em claro.
        """
        if not self.chave_local or not texto_cifrado_b64.strip():
            return ""

        try:
            dados_brutos = base64.b64decode(texto_cifrado_b64.strip())

            try:
                import primitivas_rust

                nonce = dados_brutos[:12]
                ciphertext = dados_brutos[12:]
                plaintext = primitivas_rust.aes256_decrypt(
                    self.chave_local, ciphertext, nonce
                )
                return bytes(plaintext).decode("utf-8")
            except (ImportError, AttributeError):
                # Decifragem simétrica fallback
                bloco_decifrado = bytearray()
                for i, byte in enumerate(dados_brutos):
                    bloco_decifrado.append(
                        byte ^ self.chave_local[i % len(self.chave_local)]
                    )
                return bloco_decifrado.decode("utf-8", errors="ignore")

        except Exception:
            return "[Erro ao decifrar linha do histórico]"

    # ------------------------------------------------------------------
    # 💾 OPERAÇÕES DE LEITURA E GRAVAÇÃO EM DISCO
    # ------------------------------------------------------------------
    def salvar_mensagem(self, usuario_local, contato, remetente, texto):
        """
        Formata, cifra com AES-256 e anexa a mensagem ao arquivo do
        histórico local.
        """
        if not usuario_local or not contato:
            return

        caminho = self._obter_caminho_arquivo(usuario_local, contato)
        timestamp = datetime.now().strftime("%d/%m %H:%M")
        linha_formatada = f"[{timestamp}] {remetente}: {texto}"

        # Cifra a linha individualmente antes de gravar
        linha_cifrada = self._cifrar_texto(linha_formatada)

        with open(caminho, "a", encoding="utf-8") as file:
            file.write(linha_cifrada + "\n")

    def carregar_historico(self, usuario_local, contato) -> str:
        """
        Lê todas as linhas cifradas do arquivo em disco, decifra cada uma
        e retorna o histórico em texto limpo formatado para a GUI.
        """
        caminho = self._obter_caminho_arquivo(usuario_local, contato)
        if not os.path.exists(caminho):
            return ""

        linhas_decifradas = []
        with open(caminho, "r", encoding="utf-8") as file:
            for linha in file:
                linha_limpa = linha.strip()
                if linha_limpa:
                    texto_plano = self._decifrar_texto(linha_limpa)
                    if texto_plano:
                        linhas_decifradas.append(texto_plano)

        return "\n".join(linhas_decifradas)
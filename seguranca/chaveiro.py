import os
import json
import base64

import primitivas_rust as prim

DIRETORIO_CHAVES = "chaves_locais"


class Chaveiro:
    """Gerencia o par de chaves X25519 do usuário e as chaves
    simétricas derivadas por contato (E2EE)."""

    def __init__(self, diretorio_base=DIRETORIO_CHAVES):
        self.diretorio_base = diretorio_base
        self.username = None
        self._privada = None          # bytes (32)
        self._publica = None          # bytes (32)
        self._chaves_contato = {}     # {contato: {"aes": bytes32, "hmac": bytes32}}
        os.makedirs(self.diretorio_base, exist_ok=True)

    # ------------------------------------------------------------------
    # CICLO DE VIDA
    # ------------------------------------------------------------------
    def definir_usuario(self, username):
        """Carrega (ou gera na primeira vez) o par de chaves do usuário."""
        self.username = username
        caminho = self._caminho_usuario()
        if os.path.exists(caminho):
            self._carregar(caminho)
        else:
            self._gerar_par()
            self._salvar(caminho)

    def _caminho_usuario(self):
        return os.path.join(self.diretorio_base, f"{self.username}.keys.json")

    def _gerar_par(self):
        self._privada = os.urandom(32)
        self._publica = bytes(prim.x25519_public_from_private(self._privada))

    def _salvar(self, caminho):
        dados = {
            "privada": base64.b64encode(self._privada).decode(),
            "publica": base64.b64encode(self._publica).decode(),
            "contatos": {
                c: {
                    "aes": base64.b64encode(k["aes"]).decode(),
                    "hmac": base64.b64encode(k["hmac"]).decode(),
                }
                for c, k in self._chaves_contato.items()
            },
        }
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2)

    def _carregar(self, caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            dados = json.load(f)
        self._privada = base64.b64decode(dados["privada"])
        self._publica = base64.b64decode(dados["publica"])
        self._chaves_contato = {
            c: {
                "aes": base64.b64decode(k["aes"]),
                "hmac": base64.b64decode(k["hmac"]),
            }
            for c, k in dados.get("contatos", {}).items()
        }

    # ------------------------------------------------------------------
    # ACESSO
    # ------------------------------------------------------------------
    def publica_bytes(self) -> bytes:
        return self._publica

    def publica_b64(self) -> str:
        return base64.b64encode(self._publica).decode()

    def possui_chave_contato(self, contato: str) -> bool:
        return contato in self._chaves_contato

    def obter_chaves_contato(self, contato: str):
        return self._chaves_contato.get(contato)

    # ------------------------------------------------------------------
    # NEGOCIAÇÃO COM OUTRO CONTATO
    # ------------------------------------------------------------------
    def derivar_chaves_com_contato(self, contato: str, publica_b64: str):
        """Recebe a chave pública do contato (base64), faz X25519 com a
        nossa privada e deriva AES-256 + HMAC-SHA-256 via HKDF."""
        if self._privada is None:
            raise RuntimeError("Chaveiro sem usuário definido.")

        peer_pub = base64.b64decode(publica_b64)
        segredo = bytes(prim.x25519_shared(self._privada, peer_pub))

        a, b = sorted([self.username, contato])
        info = f"e2ee|{a}|{b}".encode("utf-8")

        okm = bytes(prim.hkdf_sha256(segredo, b"", info, 64))
        aes_key = okm[:32]
        hmac_key = okm[32:]

        self._chaves_contato[contato] = {
            "aes": aes_key,
            "hmac": hmac_key,
        }
        self._salvar(self._caminho_usuario())
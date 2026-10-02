import os
import json
import base64

import primitivas_rust as prim

DIRETORIO_CHAVES = "chaves_locais"


class Chaveiro:
    """Gerencia as chaves do usuário:
       - Par X25519 para E2EE (troca de chaves com contatos)
       - Par Ed25519 para autenticação (assinatura de desafio no login)
    """

    def __init__(self, diretorio_base=DIRETORIO_CHAVES):
        self.diretorio_base = diretorio_base
        self.username = None

        # X25519 (E2EE)
        self._privada = None              # bytes (32)
        self._publica = None              # bytes (32)
        self._chaves_contato = {}         # {contato: {"aes": bytes32, "hmac": bytes32}}

        # Ed25519 (assinatura de login)
        self._priv_ed25519 = None         # bytes (32)
        self._pub_ed25519 = None          # bytes (32)

        os.makedirs(self.diretorio_base, exist_ok=True)

    # ------------------------------------------------------------------
    # CICLO DE VIDA
    # ------------------------------------------------------------------
    def definir_usuario(self, username):
        """Carrega (ou gera na primeira vez) os pares de chaves."""
        self.username = username
        caminho = self._caminho_usuario()
        if os.path.exists(caminho):
            self._carregar(caminho)
        else:
            self._gerar_par_x25519()
            self._gerar_par_ed25519()
            self._salvar(caminho)

    def _caminho_usuario(self):
        return os.path.join(
            self.diretorio_base, f"{self.username}.keys.json"
        )

    def _gerar_par_x25519(self):
        self._privada = os.urandom(32)
        self._publica = bytes(
            prim.x25519_public_from_private(self._privada)
        )

    def _gerar_par_ed25519(self):
        self._priv_ed25519 = os.urandom(32)
        self._pub_ed25519 = bytes(
            prim.ed25519_public_from_private(self._priv_ed25519)
        )

    def _salvar(self, caminho):
        dados = {
            "x25519": {
                "privada": base64.b64encode(self._privada).decode(),
                "publica": base64.b64encode(self._publica).decode(),
            },
            "ed25519": {
                "privada": base64.b64encode(self._priv_ed25519).decode(),
                "publica": base64.b64encode(self._pub_ed25519).decode(),
            },
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

        # Compatibilidade com o formato antigo (sem seções "x25519"/"ed25519")
        if "x25519" in dados:
            self._privada = base64.b64decode(dados["x25519"]["privada"])
            self._publica = base64.b64decode(dados["x25519"]["publica"])
        else:
            self._privada = base64.b64decode(dados["privada"])
            self._publica = base64.b64decode(dados["publica"])

        if "ed25519" in dados:
            self._priv_ed25519 = base64.b64decode(
                dados["ed25519"]["privada"]
            )
            self._pub_ed25519 = base64.b64decode(
                dados["ed25519"]["publica"]
            )
        else:
            # Migração: gera Ed25519 e regrava o arquivo
            self._gerar_par_ed25519()
            self._salvar(caminho)

        self._chaves_contato = {
            c: {
                "aes": base64.b64decode(k["aes"]),
                "hmac": base64.b64decode(k["hmac"]),
            }
            for c, k in dados.get("contatos", {}).items()
        }

    # ------------------------------------------------------------------
    # ACESSO — X25519 (E2EE)
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
    # ACESSO — Ed25519 (assinatura de login)
    # ------------------------------------------------------------------
    def publica_ed25519_bytes(self) -> bytes:
        return self._pub_ed25519

    def publica_ed25519_b64(self) -> str:
        return base64.b64encode(self._pub_ed25519).decode()

    def assinar_ed25519(self, mensagem: bytes) -> str:
        """Assina `mensagem` (bytes) com a privada Ed25519.

        Retorna a assinatura codificada em base64.
        """
        if self._priv_ed25519 is None:
            raise RuntimeError(
                "Chaveiro sem par Ed25519 — chame definir_usuario primeiro."
            )
        sig = bytes(prim.ed25519_sign(self._priv_ed25519, mensagem))
        return base64.b64encode(sig).decode()

    # ------------------------------------------------------------------
    # NEGOCIAÇÃO X25519 COM CONTATO (E2EE)
    # ------------------------------------------------------------------
    def derivar_chaves_com_contato(self, contato: str, publica_b64: str):
        """Deriva AES-256 + HMAC-SHA-256 com o contato via X25519+HKDF."""
        if self._privada is None:
            raise RuntimeError("Chaveiro sem usuário definido.")

        peer_pub = base64.b64decode(publica_b64)
        segredo = bytes(prim.x25519_shared(self._privada, peer_pub))

        # info idêntica nos dois lados: usernames ordenados alfabeticamente
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
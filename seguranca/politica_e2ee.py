import os
import base64

import primitivas_rust as prim


class PoliticaE2EE:
    """Implementa a dupla camada criptográfica:

    1. Camada Interna (E2EE): cifra para o destinatário.
    2. Camada Externa (Canal): cifra para o servidor.

    Se `sessao_canal` for None, a camada de canal é omitida (útil para
    testes antes do handshake DHE estar pronto).
    """

    def __init__(self, chaveiro, sessao_canal=None):
        self.chaveiro = chaveiro
        self.sessao_canal = sessao_canal

    # ------------------------------------------------------------------
    # CONSULTAS
    # ------------------------------------------------------------------
    def possui_chave_e2ee(self, contato: str) -> bool:
        return self.chaveiro.possui_chave_contato(contato)

    # ------------------------------------------------------------------
    # CIFRAGEM (envio)
    # ------------------------------------------------------------------
    def cifrar_dupla_camada(self, destinatario: str, texto_plano: str) -> str:
        """Cifra `texto_plano` em duas camadas e devolve base64."""
        if not self.possui_chave_e2ee(destinatario):
            raise ValueError(
                f"Sem chave E2EE negociada com {destinatario}."
            )

        chaves = self.chaveiro.obter_chaves_contato(destinatario)
        aes_key = chaves["aes"]
        hmac_key = chaves["hmac"]

        texto_bytes = texto_plano.encode("utf-8")

        # ---- Camada Interna (E2EE) ----
        nonce_e2ee = os.urandom(12)
        ct_e2ee = bytes(prim.aes256_encrypt(aes_key, texto_bytes, nonce_e2ee))
        tag_e2ee = bytes(prim.hmac_sha256(hmac_key, nonce_e2ee + ct_e2ee))
        pacote_interno = nonce_e2ee + ct_e2ee + tag_e2ee  # 12 + N + 32

        # ---- Camada Externa (Canal) ----
        if self.sessao_canal is not None:
            canal = self.sessao_canal.obter_chaves()
            nonce_canal = os.urandom(12)
            ct_canal = bytes(
                prim.aes256_encrypt(canal["aes"], pacote_interno, nonce_canal)
            )
            tag_canal = bytes(
                prim.hmac_sha256(canal["hmac"], nonce_canal + ct_canal)
            )
            pacote_final = nonce_canal + ct_canal + tag_canal
        else:
            # Sem canal: só empacota a camada interna
            pacote_final = pacote_interno

        return base64.b64encode(pacote_final).decode("utf-8")

    # ------------------------------------------------------------------
    # DECIFRAGEM (recebimento)
    # ------------------------------------------------------------------
    def decifrar_camada_canal(self, dados_brutos: str) -> str:
        """Decifra apenas a camada externa (canal). Devolve o conteúdo
        interno ainda cifrado, codificado em base64 — ou o próprio texto
        se não houver canal."""
        if self.sessao_canal is None:
            # Sem canal: os dados chegam como texto do protocolo
            return dados_brutos

        try:
            pacote = base64.b64decode(dados_brutos.strip())
        except Exception:
            return dados_brutos

        if len(pacote) < 12 + 16 + 32:
            return dados_brutos  # não é pacote de canal

        canal = self.sessao_canal.obter_chaves()
        nonce = pacote[:12]
        tag = pacote[-32:]
        ct = pacote[12:-32]

        if not prim.hmac_sha256_verify(canal["hmac"], nonce + ct, tag):
            raise ValueError("HMAC do canal inválido — pacote rejeitado.")

        pt = bytes(prim.aes256_decrypt(canal["aes"], ct, nonce))
        return base64.b64encode(pt).decode("utf-8")

    def decifrar_camada_e2ee(self, remetente: str, pacote_b64: str) -> str:
        """Decifra a camada interna E2EE de um pacote base64."""
        if not self.possui_chave_e2ee(remetente):
            return None

        try:
            pacote = base64.b64decode(pacote_b64.strip())
        except Exception:
            return None

        if len(pacote) < 12 + 1 + 32:
            return None

        chaves = self.chaveiro.obter_chaves_contato(remetente)
        nonce = pacote[:12]
        tag = pacote[-32:]
        ct = pacote[12:-32]

        if not prim.hmac_sha256_verify(chaves["hmac"], nonce + ct, tag):
            return None

        try:
            pt = bytes(prim.aes256_decrypt(chaves["aes"], ct, nonce))
            return pt.decode("utf-8")
        except Exception:
            return None

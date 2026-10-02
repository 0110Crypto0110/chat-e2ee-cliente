"""Teste completo do cliente - com validação detalhada.

Rodar com o venv do cliente ativo:
    python teste_cliente_completo.py
"""

import os
import shutil
import base64
import time


# ---------------------------------------------------------------------
# Helpers de exibição
# ---------------------------------------------------------------------
class Teste:
    def __init__(self):
        self.ok = 0
        self.falhou = 0
        self.erros = []

    def secao(self, titulo):
        print()
        print("─" * 72)
        print(f"  {titulo}")
        print("─" * 72)

    def check(self, nome, condicao, detalhe=""):
        if condicao:
            print(f"  ✅ {nome}")
            if detalhe:
                print(f"     {detalhe}")
            self.ok += 1
        else:
            print(f"  ❌ {nome}")
            if detalhe:
                print(f"     {detalhe}")
            self.falhou += 1
            self.erros.append(nome)
        return condicao

    def iguais(self, nome, a, b, mostrar=True):
        ok = a == b
        if mostrar:
            sa = self.resumo_bytes(a)
            sb = self.resumo_bytes(b)
            det = f"A={sa}   B={sb}"
        else:
            det = ""
        return self.check(nome, ok, det)

    def diferentes(self, nome, a, b, mostrar=True):
        ok = a != b
        if mostrar:
            sa = self.resumo_bytes(a)
            sb = self.resumo_bytes(b)
            det = f"A={sa}   B={sb}"
        else:
            det = ""
        return self.check(nome, ok, det)

    @staticmethod
    def resumo_bytes(v, n=16):
        if isinstance(v, bytes):
            h = v.hex()
            return f"{h[:n]}…{h[-n:]}" if len(h) > n * 2 else h
        if isinstance(v, str):
            return f"{v[:n]}…{v[-n:]}" if len(v) > n * 2 else v
        return str(v)[:40]

    def resumo(self):
        print()
        print("═" * 72)
        print(f"  RESUMO FINAL")
        print("═" * 72)
        print(f"  Total de checks: {self.ok + self.falhou}")
        print(f"  ✅ Passaram: {self.ok}")
        print(f"  ❌ Falharam: {self.falhou}")
        if self.erros:
            print()
            print("  Checks que falharam:")
            for e in self.erros:
                print(f"    • {e}")
        print()


t = Teste()


# ---------------------------------------------------------------------
# 1. primitivas_rust
# ---------------------------------------------------------------------
def teste_primitivas_rust():
    t.secao("1. primitivas_rust — funções Rust (cliente)")

    try:
        import primitivas_rust as pr
    except ImportError as e:
        t.check("import primitivas_rust", False, str(e))
        return

    t.check("import primitivas_rust", True, f"arquivo: {pr.__file__}")

    # --- AES-256-GCM ---
    print()
    print("  ── AES-256-GCM ──")
    k = os.urandom(32)
    n = os.urandom(12)
    texto = b"mensagem secreta"
    ct = bytes(pr.aes256_encrypt(k, texto, n))
    pt = bytes(pr.aes256_decrypt(k, ct, n))
    print(f"     plaintext : {texto!r}")
    print(f"     ciphertext: {t.resumo_bytes(ct)}  ({len(ct)} bytes)")
    t.iguais("AES roundtrip devolve original", pt, texto)

    # Nonce diferente -> ciphertext diferente
    n2 = os.urandom(12)
    ct2 = bytes(pr.aes256_encrypt(k, texto, n2))
    t.diferentes("nonce diferente gera ciphertext diferente", ct, ct2)

    # Chave errada -> falha de autenticação
    k_errada = os.urandom(32)
    try:
        pr.aes256_decrypt(k_errada, ct, n)
        t.check("chave errada rejeitada", False, "decifrou sem erro!")
    except Exception as e:
        t.check(
            "chave errada rejeitada",
            True,
            f"levantou: {type(e).__name__}",
        )

    # --- HMAC-SHA-256 ---
    print()
    print("  ── HMAC-SHA-256 ──")
    key = os.urandom(32)
    msg = b"pacote de teste"
    tag = bytes(pr.hmac_sha256(key, msg))
    print(f"     mensagem: {msg!r}")
    print(f"     tag     : {t.resumo_bytes(tag)}  ({len(tag)} bytes)")
    t.check("tag tem 32 bytes (SHA-256)", len(tag) == 32)
    t.check("verify correto", pr.hmac_sha256_verify(key, msg, tag))
    t.check(
        "verify mensagem alterada = False",
        not pr.hmac_sha256_verify(key, b"outra mensagem", tag),
    )
    tag_adulterada = bytes([tag[0] ^ 0xFF]) + tag[1:]
    t.check(
        "verify tag adulterada = False",
        not pr.hmac_sha256_verify(key, msg, tag_adulterada),
    )

    # --- HKDF-SHA-256 ---
    print()
    print("  ── HKDF-SHA-256 ──")
    ikm = os.urandom(32)
    salt = os.urandom(16)
    info = b"canal-cliente-servidor"
    okm64 = bytes(pr.hkdf_sha256(ikm, salt, info, 64))
    print(f"     IKM  : {t.resumo_bytes(ikm)}")
    print(f"     salt : {t.resumo_bytes(salt)}")
    print(f"     info : {info!r}")
    print(f"     OKM  : {t.resumo_bytes(okm64)}  ({len(okm64)} bytes)")
    t.check("HKDF gera 64 bytes", len(okm64) == 64)

    aes_key = okm64[:32]
    hmac_key = okm64[32:]
    t.check(
        "primeiros 32B (AES) != últimos 32B (HMAC)",
        aes_key != hmac_key,
    )

    # Determinismo
    okm64_repeat = bytes(pr.hkdf_sha256(ikm, salt, info, 64))
    t.iguais("HKDF determinístico (mesmo input)", okm64, okm64_repeat)

    # Info diferente -> OKM diferente
    okm_outro = bytes(pr.hkdf_sha256(ikm, salt, b"outra-info", 64))
    t.diferentes("info diferente gera OKM diferente", okm64, okm_outro)

    # --- X25519 ---
    print()
    print("  ── X25519 (Diffie-Hellman) ──")
    a_priv = os.urandom(32)
    b_priv = os.urandom(32)
    a_pub = bytes(pr.x25519_public_from_private(a_priv))
    b_pub = bytes(pr.x25519_public_from_private(b_priv))
    print(f"     Alice priv: {t.resumo_bytes(a_priv)}")
    print(f"     Alice pub : {t.resumo_bytes(a_pub)}")
    print(f"     Bob   priv: {t.resumo_bytes(b_priv)}")
    print(f"     Bob   pub : {t.resumo_bytes(b_pub)}")

    t.check("chave pública tem 32 bytes", len(a_pub) == 32)
    t.diferentes("priv != pub", a_priv, a_pub)

    seg_a = bytes(pr.x25519_shared(a_priv, b_pub))
    seg_b = bytes(pr.x25519_shared(b_priv, a_pub))
    print(f"     Alice calcula: {t.resumo_bytes(seg_a)}")
    print(f"     Bob   calcula: {t.resumo_bytes(seg_b)}")
    t.iguais("segredo compartilhado bate", seg_a, seg_b)
    t.check("segredo tem 32 bytes", len(seg_a) == 32)

    # Clamping: privada com bits extremos deve gerar mesma pública
    priv_raw = bytearray(os.urandom(32))
    pub1 = bytes(pr.x25519_public_from_private(bytes(priv_raw)))
    priv_raw[0] |= 0x07   # bits que o clamp zera
    priv_raw[31] |= 0x80  # bit que o clamp zera
    pub2 = bytes(pr.x25519_public_from_private(bytes(priv_raw)))
    t.iguais("clamp RFC 7748 aplicado (bits irrelevantes ignorados)", pub1, pub2)

    # --- Ed25519 ---
    print()
    print("  ── Ed25519 (assinatura) ──")
    priv = os.urandom(32)
    pub = bytes(pr.ed25519_public_from_private(priv))
    desafio = b"nonce-aleatorio-do-servidor"
    sig = bytes(pr.ed25519_sign(priv, desafio))
    print(f"     privada    : {t.resumo_bytes(priv)}")
    print(f"     pública    : {t.resumo_bytes(pub)}")
    print(f"     desafio    : {desafio!r}")
    print(f"     assinatura : {t.resumo_bytes(sig)}  ({len(sig)} bytes)")

    t.check("pública tem 32 bytes", len(pub) == 32)
    t.check("assinatura tem 64 bytes", len(sig) == 64)
    t.check("verify correto", pr.ed25519_verify(pub, desafio, sig))
    t.check(
        "verify com mensagem errada = False",
        not pr.ed25519_verify(pub, b"outro desafio", sig),
    )

    # Assinatura diferente a cada chamada (Ed25519 é determinístico)
    sig2 = bytes(pr.ed25519_sign(priv, desafio))
    t.iguais("Ed25519 é determinístico (mesma entrada)", sig, sig2)

    # Chave pública errada -> falha
    outra_pub = bytes(pr.ed25519_public_from_private(os.urandom(32)))
    t.check(
        "verify com pública errada = False",
        not pr.ed25519_verify(outra_pub, desafio, sig),
    )


# ---------------------------------------------------------------------
# 2. Chaveiro
# ---------------------------------------------------------------------
def teste_chaveiro():
    t.secao("2. Chaveiro (X25519 + Ed25519 + persistência)")
    dir_teste = "_chaves_teste"
    shutil.rmtree(dir_teste, ignore_errors=True)

    try:
        from seguranca.chaveiro import Chaveiro
    except Exception as e:
        t.check("import chaveiro", False, str(e))
        return

    try:
        c = Chaveiro(diretorio_base=dir_teste)
        c.definir_usuario("alice")

        t.check(
            "X25519 pública gerada (32 bytes)",
            len(c.publica_bytes()) == 32,
            f"pub_x25519 = {c.publica_b64()[:24]}…",
        )
        t.check(
            "Ed25519 pública gerada (32 bytes)",
            len(c.publica_ed25519_bytes()) == 32,
            f"pub_ed25519 = {c.publica_ed25519_b64()[:24]}…",
        )

        # Arquivo em disco
        caminho = os.path.join(dir_teste, "alice.keys.json")
        t.check("arquivo .keys.json criado", os.path.exists(caminho))

        with open(caminho, "r", encoding="utf-8") as f:
            import json
            dados = json.load(f)
        t.check(
            "JSON tem seção x25519 e ed25519",
            "x25519" in dados and "ed25519" in dados,
        )

        # Assinatura
        nonce = os.urandom(32)
        sig_b64 = c.assinar_ed25519(nonce)
        t.check(
            "assinatura Ed25519 gerada (base64)",
            isinstance(sig_b64, str) and len(sig_b64) > 0,
            f"sig = {sig_b64[:24]}…",
        )

        # Persistência — recarrega do disco
        c2 = Chaveiro(diretorio_base=dir_teste)
        c2.definir_usuario("alice")
        t.iguais(
            "pública X25519 persistiu",
            c2.publica_b64(),
            c.publica_b64(),
        )
        t.iguais(
            "pública Ed25519 persistiu",
            c2.publica_ed25519_b64(),
            c.publica_ed25519_b64(),
        )

        # Segunda assinatura com chave recarregada = mesmo resultado
        sig_b64_2 = c2.assinar_ed25519(nonce)
        t.iguais(
            "chave privada Ed25519 persistiu (assinatura idêntica)",
            sig_b64,
            sig_b64_2,
        )

        # Derivação E2EE entre dois usuários
        print()
        print("  ── Derivação E2EE alice ↔ bob ──")
        bob = Chaveiro(diretorio_base=dir_teste)
        bob.definir_usuario("bob")

        c.derivar_chaves_com_contato("bob", bob.publica_b64())
        bob.derivar_chaves_com_contato("alice", c.publica_b64())

        ka = c.obter_chaves_contato("bob")
        kb = bob.obter_chaves_contato("alice")
        print(f"     alice.aes : {t.resumo_bytes(ka['aes'])}")
        print(f"     bob.aes   : {t.resumo_bytes(kb['aes'])}")
        print(f"     alice.hmac: {t.resumo_bytes(ka['hmac'])}")
        print(f"     bob.hmac  : {t.resumo_bytes(kb['hmac'])}")
        t.iguais("chave AES bate", ka["aes"], kb["aes"])
        t.iguais("chave HMAC bate", ka["hmac"], kb["hmac"])

        # Chaves de alice para bob != chaves de alice para carol
        carol = Chaveiro(diretorio_base=dir_teste)
        carol.definir_usuario("carol")
        c.derivar_chaves_com_contato("carol", carol.publica_b64())
        kc = c.obter_chaves_contato("carol")
        t.diferentes(
            "chave para contatos diferentes é diferente",
            ka["aes"],
            kc["aes"],
        )
    finally:
        shutil.rmtree(dir_teste, ignore_errors=True)


# ---------------------------------------------------------------------
# 3. politica_e2ee
# ---------------------------------------------------------------------
def teste_politica_e2ee():
    t.secao("3. Política E2EE (dupla camada)")
    dir_teste = "_chaves_teste"
    shutil.rmtree(dir_teste, ignore_errors=True)

    try:
        from seguranca.chaveiro import Chaveiro
        from seguranca.politica_e2ee import PoliticaE2EE
    except Exception as e:
        t.check("import politica_e2ee", False, str(e))
        return

    try:
        alice = Chaveiro(diretorio_base=dir_teste)
        alice.definir_usuario("alice")
        bob = Chaveiro(diretorio_base=dir_teste)
        bob.definir_usuario("bob")

        alice.derivar_chaves_com_contato("bob", bob.publica_b64())
        bob.derivar_chaves_com_contato("alice", alice.publica_b64())

        pol_a = PoliticaE2EE(alice)
        pol_b = PoliticaE2EE(bob)

        # Cifra
        texto = "mensagem ultra secreta"
        pacote = pol_a.cifrar_dupla_camada("bob", texto)
        print(f"     texto claro: {texto!r}")
        print(f"     pacote E2EE: {pacote[:60]}…  ({len(pacote)} chars)")
        t.check("pacote E2EE gerado", isinstance(pacote, str) and len(pacote) > 0)

        # Decifra
        decifrado = pol_b.decifrar_camada_e2ee("alice", pacote)
        print(f"     decifrado  : {decifrado!r}")
        t.iguais("bob decifrou corretamente", decifrado, texto)

        # Não pode decifrar sem a chave
        carol = Chaveiro(diretorio_base=dir_teste)
        carol.definir_usuario("carol")
        pol_c = PoliticaE2EE(carol)
        t.check(
            "sem chave E2EE do remetente, decifra retorna None",
            pol_c.decifrar_camada_e2ee("alice", pacote) is None,
        )

        # Pacote adulterado (muda 1 char)
        pacote_adulterado = pacote[:10] + (
            "A" if pacote[10] != "A" else "B"
        ) + pacote[11:]
        resultado_adulterado = pol_b.decifrar_camada_e2ee(
            "alice", pacote_adulterado
        )
        t.check(
            "pacote adulterado é rejeitado (HMAC)",
            resultado_adulterado is None,
        )

        # Duas cifragens do mesmo texto geram pacotes diferentes (nonce aleatório)
        pacote2 = pol_a.cifrar_dupla_camada("bob", texto)
        t.diferentes(
            "duas cifragens do mesmo texto → pacotes diferentes",
            pacote,
            pacote2,
        )
    finally:
        shutil.rmtree(dir_teste, ignore_errors=True)


# ---------------------------------------------------------------------
# 4. historico_local
# ---------------------------------------------------------------------
def teste_historico():
    t.secao("4. Histórico local cifrado (AES no disco)")
    dir_teste = "_hist_teste"
    shutil.rmtree(dir_teste, ignore_errors=True)

    try:
        from infraestrutura.historico_local import HistoricoLocal
    except Exception as e:
        t.check("import historico_local", False, str(e))
        return

    try:
        h = HistoricoLocal(diretorio_base=dir_teste)
        h.definir_usuario("alice")

        msg1 = "primeira mensagem secreta"
        msg2 = "segunda mensagem confidencial"
        h.salvar_mensagem("alice", "bob", "Voce", msg1)
        h.salvar_mensagem("alice", "bob", "bob", msg2)

        # Verifica que o arquivo existe e está cifrado
        caminho = os.path.join(dir_teste, "alice_bob.dat")
        t.check("arquivo .dat criado", os.path.exists(caminho))

        with open(caminho, "r", encoding="utf-8") as f:
            conteudo = f.read()

        print(f"     arquivo em disco ({len(conteudo)} chars):")
        primeira_linha = conteudo.split("\n")[0]
        print(f"       {primeira_linha[:60]}…")

        t.check(
            "arquivo NÃO contém texto claro (msg1)",
            msg1 not in conteudo,
        )
        t.check(
            "arquivo NÃO contém texto claro (msg2)",
            msg2 not in conteudo,
        )
        t.check(
            "arquivo NÃO contém nome de usuário em claro",
            "alice" not in conteudo and "bob" not in conteudo,
        )

        # Decifra corretamente
        texto = h.carregar_historico("alice", "bob")
        print(f"     decifrado:")
        for linha in texto.split("\n"):
            print(f"       {linha}")
        t.check("msg1 está no histórico decifrado", msg1 in texto)
        t.check("msg2 está no histórico decifrado", msg2 in texto)
        t.check(
            "remetentes corretos",
            "Voce:" in texto and "bob:" in texto,
        )

        # Chave errada
        outro = HistoricoLocal(diretorio_base=dir_teste)
        outro.definir_usuario("outro_usuario")
        texto_errado = outro.carregar_historico("alice", "bob")
        t.check(
            "chave errada não decifra (retorna erro/vazio)",
            msg1 not in texto_errado,
        )
    finally:
        shutil.rmtree(dir_teste, ignore_errors=True)


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------
def main():
    print()
    print("╔" + "═" * 70 + "╗")
    print("║" + "  TESTE COMPLETO DO CLIENTE".center(70) + "║")
    print("║" + f"  Python: {os.sys.executable}".center(70)[:70] + "║")
    print("╚" + "═" * 70 + "╝")

    t0 = time.time()
    teste_primitivas_rust()
    teste_chaveiro()
    teste_politica_e2ee()
    teste_historico()
    dur = time.time() - t0

    t.resumo()
    print(f"  Tempo total: {dur:.2f}s")
    print()


if __name__ == "__main__":
    main()
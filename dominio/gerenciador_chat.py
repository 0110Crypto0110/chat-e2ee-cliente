import os
import time
from infraestrutura.historico_local import HistoricoLocal
from seguranca.chaveiro import Chaveiro
from seguranca.politica_e2ee import PoliticaE2EE


class GerenciadorChat:
    def __init__(self, rede_cliente, politica_e2ee=None, chaveiro=None):
        self.rede = rede_cliente

        # Camada de segurança: se não vierem injetados, cria os padrões
        self.chaveiro = chaveiro or Chaveiro()
        self.politica_e2ee = politica_e2ee or PoliticaE2EE(self.chaveiro)

        self.historico = HistoricoLocal()

        # Estado do usuário e da sessão
        self.current_username = None
        self.chatting_with = None
        self.contacts = []

        # Buffer de mensagens E2EE aguardando negociação de chave
        # Cada item é uma tupla (remetente, pacote_b64)
        self._pending_e2ee = []

        # Controle do status 'digitando'
        self.is_typing = False
        self.last_key_press_time = 0

        # Callbacks para a camada de Apresentação (GUI Tkinter)
        self.cb_login_success = None
        self.cb_message_received = None
        self.cb_contacts_updated = None
        self.cb_typing_status = None
        self.cb_info = None
        self.cb_error = None

    def set_gui_callbacks(
        self,
        on_login_success,
        on_message_received,
        on_contacts_updated,
        on_typing_status,
        on_info,
        on_error,
    ):
        """Registra as funções de atualização da interface gráfica."""
        self.cb_login_success = on_login_success
        self.cb_message_received = on_message_received
        self.cb_contacts_updated = on_contacts_updated
        self.cb_typing_status = on_typing_status
        self.cb_info = on_info
        self.cb_error = on_error

    # ------------------------------------------------------------------
    # 👤 AUTENTICAÇÃO E REGISTRO
    # ------------------------------------------------------------------
    def fazer_login(self, username, password):
        """Executa a conexão socket e solicita o login ao servidor."""
        if not self.rede.conectar():
            if self.cb_error:
                self.cb_error(
                    "Erro de Conexão",
                    "Não foi possível conectar ao servidor.",
                )
            return

        mensagem_login = f"LOGIN|{username}|{password}"
        sucesso, resposta = self.rede.enviar_e_receber(mensagem_login)

        if sucesso and resposta.startswith("LOGIN_OK"):
            self.current_username = username

            # Configura o histórico local cifrado
            self.historico.definir_usuario(username)

            # Carrega (ou gera) o par de chaves X25519 do usuário
            self.chaveiro.definir_usuario(username)

            # Inicia a thread de escuta contínua de mensagens da rede
            self.rede.iniciar_escuta(self.processar_pacote_recebido)

            # Publica a chave pública no servidor para que outros
            # usuários possam negociar E2EE conosco.
            self.rede.enviar_comando(
                f"SET_PUBKEY|{self.chaveiro.publica_b64()}"
            )

            if self.cb_login_success:
                self.cb_login_success()
        else:
            self.rede.desconectar()
            if self.cb_error:
                self.cb_error(
                    "Login Falhou",
                    resposta if resposta else "Credenciais inválidas.",
                )

    def fazer_registro(self, username, password):
        """Solicita o cadastro de um novo usuário."""
        if not self.rede.conectar():
            if self.cb_error:
                self.cb_error(
                    "Erro de Conexão",
                    "Não foi possível conectar ao servidor.",
                )
            return

        mensagem_registro = f"REGISTER|{username}|{password}"
        sucesso, resposta = self.rede.enviar_e_receber(mensagem_registro)

        self.rede.desconectar()
        if sucesso:
            if self.cb_info:
                self.cb_info("Registro", resposta)
        else:
            if self.cb_error:
                self.cb_error("Erro de Registro", resposta)

    # ------------------------------------------------------------------
    # 📇 GESTÃO DE CONTATOS E HISTÓRICO
    # ------------------------------------------------------------------
    def obter_lista_contatos(self):
        """Solicita ao servidor a lista atualizada de usuários e status."""
        self.rede.enviar_comando("GET_CONTACTS")

    def selecionar_contato(self, contato):
        """Define o contato ativo da conversa."""
        self.chatting_with = contato

        # Se ainda não temos a chave E2EE deste contato, pedimos ao servidor
        if not self.chaveiro.possui_chave_contato(contato):
            self.rede.enviar_comando(f"GET_PUBKEY|{contato}")

    def carregar_historico_contato(self, contato):
        """Lê o histórico de mensagens local cifrado com AES-256."""
        return self.historico.carregar_historico(
            self.current_username, contato
        )

    # ------------------------------------------------------------------
    # 💬 ENVIO E RECEBIMENTO DE MENSAGENS (COM E2EE)
    # ------------------------------------------------------------------
    def enviar_mensagem(self, texto_plano):
        """
        Prepara e envia uma mensagem aplicando a dupla camada criptográfica:
        1. Camada Interna (E2EE): Cifra para o destinatário.
        2. Camada Externa (Canal): Cifra para o servidor.
        """
        if not self.chatting_with:
            return False, "Nenhum contato selecionado."

        # Regra de Segurança E2EE Offline:
        # Se não há chave E2EE negociada com o contato, precisamos dele
        # online para negociar em tempo real.
        if not self.politica_e2ee.possui_chave_e2ee(self.chatting_with):
            if not self.esta_online(self.chatting_with):
                return (
                    False,
                    f"Não foi possível entregar a mensagem para "
                    f"{self.chatting_with} por questões de segurança "
                    f"(sem chave E2EE prévia).",
                )
            # Pede a chave pública e avisa o usuário para tentar de novo
            self.rede.enviar_comando(
                f"GET_PUBKEY|{self.chatting_with}"
            )
            return (
                False,
                f"Chave E2EE de {self.chatting_with} ainda não foi "
                f"negociada. Aguarde alguns segundos e tente novamente.",
            )

        # Cifra em dupla camada
        pacote_cifrado = self.politica_e2ee.cifrar_dupla_camada(
            destinatario=self.chatting_with,
            texto_plano=texto_plano,
        )
        comando_envio = (
            f"MESSAGE_E2EE|{self.chatting_with}|{pacote_cifrado}"
        )

        enviado = self.rede.enviar_comando(comando_envio)
        if enviado:
            self.historico.salvar_mensagem(
                usuario_local=self.current_username,
                contato=self.chatting_with,
                remetente="Você",
                texto=texto_plano,
            )
            return True, None
        return False, "Falha na conexão de rede ao enviar mensagem."

    def processar_pacote_recebido(self, dados_brutos):
        """
        Thread Callback: Recebe os bytes do socket, decifra as camadas de
        segurança e atualiza a interface gráfica.
        """
        print(f"[DEBUG RECV] bruto: {dados_brutos[:80]!r}")

        # Decifra a camada externa do canal (se houver)
        try:
            dados_decifrados = self.politica_e2ee.decifrar_camada_canal(
                dados_brutos
            )
        except Exception:
            dados_decifrados = dados_brutos

        print(f"[DEBUG RECV] decifrado: {dados_decifrados[:80]!r}")

        if not dados_decifrados:
            return

        partes = dados_decifrados.split("|")
        comando = partes[0]

         # ---------------- MENSAGEM SIMPLES (sem E2EE) ----------------
        if comando == "MESSAGE":
            remetente = partes[1]
            texto = partes[2]

            self.historico.salvar_mensagem(
                self.current_username, remetente, remetente, texto
            )
            if self.cb_message_received:
                self.cb_message_received(remetente, texto)

        # ---------------- MENSAGEM CIFRADA E2EE ----------------
        elif comando == "MESSAGE_E2EE":
            remetente = partes[1]
            pacote_e2ee = partes[2]

            texto_plano = self.politica_e2ee.decifrar_camada_e2ee(
                remetente, pacote_e2ee
            )
            print(f"[TESTE] texto_plano={texto_plano!r}")

            if texto_plano:
                self.historico.salvar_mensagem(
                    self.current_username,
                    remetente,
                    remetente,
                    texto_plano,
                )
                if self.cb_message_received:
                    self.cb_message_received(remetente, texto_plano)
            else:
                print(
                    f"[DEBUG] Bufferizando msg de {remetente}, "
                    f"pedindo chave..."
                )
                self._pending_e2ee.append((remetente, pacote_e2ee))
                self.rede.enviar_comando(f"GET_PUBKEY|{remetente}")
                print(f"[DEBUG] Enviado GET_PUBKEY|{remetente}")
                if self.cb_info:
                    self.cb_info(
                        "Mensagem cifrada",
                        f"Mensagem de {remetente} aguardando "
                        f"negociação de chave.",
                    )

        # ---------------- RESPOSTA DE GET_PUBKEY ----------------
        elif comando == "PUBKEY":
            print(f"[DEBUG] PUBKEY recebido! partes={partes[:2]}")
            contato = partes[1]
            chave_b64 = partes[2]
            try:
                self.chaveiro.derivar_chaves_com_contato(
                    contato, chave_b64
                )

                # Tenta decifrar as mensagens pendentes deste contato
                restantes = []
                for remetente, pacote in self._pending_e2ee:
                    if remetente != contato:
                        restantes.append((remetente, pacote))
                        continue
                    texto = self.politica_e2ee.decifrar_camada_e2ee(
                        remetente, pacote
                    )
                    if texto:
                        self.historico.salvar_mensagem(
                            self.current_username,
                            remetente,
                            remetente,
                            texto,
                        )
                        if self.cb_message_received:
                            self.cb_message_received(remetente, texto)
                    else:
                        restantes.append((remetente, pacote))
                self._pending_e2ee = restantes

                if self.cb_info:
                    self.cb_info(
                        "Chave E2EE",
                        f"Chave E2EE negociada com {contato}.",
                    )
            except Exception as e:
                import traceback
                print(f"[TESTE] EXCECAO no PUBKEY: {e!r}")
                traceback.print_exc()
                if self.cb_error:
                    self.cb_error(
                        "Erro de Chave",
                        f"Falha ao negociar chave com {contato}: {e}",
                    )

        # ---------------- ATUALIZAÇÃO DA LISTA DE CONTATOS ----------------
        elif comando == "CONTACTS_LIST":
            self.contacts = partes[1:]
            formatados = [
                c
                for c in self.contacts
                if not c.startswith(f"{self.current_username}:")
            ]
            if self.cb_contacts_updated:
                self.cb_contacts_updated(formatados)

        # ---------------- INDICADOR "DIGITANDO..." ----------------
        elif comando == "TYPING":
            remetente = partes[1]
            if self.cb_typing_status:
                self.cb_typing_status(remetente, True)

        elif comando == "TYPING_STOP":
            remetente = partes[1]
            if self.cb_typing_status:
                self.cb_typing_status(remetente, False)

        # ---------------- INFO / ERRO ----------------
        elif comando == "INFO":
            if self.cb_info:
                self.cb_info("Informação", partes[1])

        elif comando == "ERROR":
            if self.cb_error:
                self.cb_error("Erro", partes[1])

    # ------------------------------------------------------------------
    # ⌨️ NOTIFICAÇÕES DE DIGITAÇÃO E STATUS
    # ------------------------------------------------------------------
    def notificar_digitando(self):
        if self.chatting_with and not self.is_typing:
            self.is_typing = True
            self.rede.enviar_comando(f"TYPING|{self.chatting_with}")

    def notificar_parou_digitando(self):
        if self.chatting_with and self.is_typing:
            self.is_typing = False
            self.rede.enviar_comando(f"TYPING_STOP|{self.chatting_with}")

    def esta_online(self, contato):
        for entry in self.contacts:
            if entry.startswith(f"{contato}:online"):
                return True
        return False

    def desconectar(self):
        """Encerra graciosamente a sessão e os sockets de rede."""
        if self.current_username:
            self.rede.enviar_comando("LOGOUT")
        self.rede.desconectar()
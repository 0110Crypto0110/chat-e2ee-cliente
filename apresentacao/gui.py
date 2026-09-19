import tkinter as tk
from tkinter import messagebox
import threading



class ChatClientGUI:
    def __init__(self, master, gerenciador):
        self.master = master
        self.gerenciador = gerenciador

        self.master.title("Chat - Login")
        self.master.geometry("350x220")

        # Conecta os callbacks do gerenciador à interface gráfica
        self.gerenciador.set_gui_callbacks(
            on_login_success=self.show_chat_window,
            on_message_received=self.handle_message_received,
            on_contacts_updated=self.update_contacts_list,
            on_typing_status=self.update_typing_status,
            on_info=self.show_info,
            on_error=self.show_error,
        )

        self.login_frame = self.create_login_frame()

    def create_login_frame(self):
        """Cria a tela inicial de Login e Registro."""
        frame = tk.Frame(self.master, padx=15, pady=15)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            frame, text="Nome de Usuário:", font=("Arial", 10)
        ).grid(row=0, column=0, pady=5, sticky="w")

        self.entry_username = tk.Entry(frame, font=("Arial", 10))
        self.entry_username.grid(row=0, column=1, pady=5)

        tk.Label(frame, text="Senha:", font=("Arial", 10)).grid(
            row=1, column=0, pady=5, sticky="w"
        )

        self.entry_password = tk.Entry(frame, show="*", font=("Arial", 10))
        self.entry_password.grid(row=1, column=1, pady=5)

        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)

        tk.Button(
            btn_frame, text="Login", width=10, command=self.handle_login
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            btn_frame, text="Registrar", width=10, command=self.handle_register
        ).pack(side=tk.RIGHT, padx=5)

        return frame

    def handle_login(self):
        """Captura os dados e solicita login ao Gerenciador."""
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if username and password:
            threading.Thread(
                target=self.gerenciador.fazer_login,
                args=(username, password),
                daemon=True,
            ).start()
        else:
            messagebox.showwarning("Aviso", "Preencha usuário e senha.")

    def handle_register(self):
        """Captura os dados e solicita registro ao Gerenciador."""
        username = self.entry_username.get().strip()
        password = self.entry_password.get().strip()

        if username and password:
            threading.Thread(
                target=self.gerenciador.fazer_registro,
                args=(username, password),
                daemon=True,
            ).start()
        else:
            messagebox.showwarning("Aviso", "Preencha usuário e senha.")

    def show_chat_window(self):
        """Destroi a tela de login e constrói a janela principal do chat."""
        if self.login_frame:
            self.login_frame.destroy()

        username = self.gerenciador.current_username
        self.master.title(f"Chat - {username}")
        self.master.geometry("800x600")

        main_frame = tk.Frame(self.master)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Painel Esquerdo: Lista de Contatos
        contacts_frame = tk.Frame(main_frame, width=220, bg="#f0f0f0")
        contacts_frame.pack(side=tk.LEFT, fill=tk.Y)
        contacts_frame.pack_propagate(False)

        tk.Label(
            contacts_frame,
            text="Contatos",
            bg="#4a7abc",
            fg="white",
            font=("Arial", 11, "bold"),
        ).pack(fill=tk.X)

        self.contacts_listbox = tk.Listbox(
            contacts_frame,
            font=("Arial", 10),
            selectbackground="#d0e0f0",
        )
        self.contacts_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.contacts_listbox.bind("<<ListboxSelect>>", self.on_contact_select)

        # Painel Direito: Histórico de Conversa e Entrada
        chat_frame = tk.Frame(main_frame)
        chat_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        self.chat_history = tk.Text(
            chat_frame, state="disabled", wrap="word", font=("Arial", 10)
        )
        self.chat_history.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.typing_label = tk.Label(
            chat_frame, text="", font=("Arial", 9, "italic"), fg="gray"
        )
        self.typing_label.pack(anchor="w", padx=5)

        # Barra inferior de envio
        message_frame = tk.Frame(chat_frame)
        message_frame.pack(fill=tk.X, padx=5, pady=5)

        self.message_entry = tk.Entry(message_frame, font=("Arial", 11))
        self.message_entry.pack(
            side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5)
        )
        self.message_entry.bind("<Return>", lambda event: self.send_message())
        self.message_entry.bind("<Key>", self.handle_key_press)

        self.send_button = tk.Button(
            message_frame,
            text="Enviar",
            width=10,
            bg="#4a7abc",
            fg="white",
            command=self.send_message,
        )
        self.send_button.pack(side=tk.RIGHT)

        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Solicita a lista inicial de contatos ao servidor
        self.gerenciador.obter_lista_contatos()

    def on_contact_select(self, event):
        """Trata a seleção de um contato na lista."""
        print("[GUI] on_contact_select disparou")
        selected_index = self.contacts_listbox.curselection()
        print(f"[GUI] selected_index = {selected_index}")
        if selected_index:
            contact = self.contacts_listbox.get(selected_index)
            print(f"[GUI] contact = {contact!r}")
            self.gerenciador.selecionar_contato(contact)
            print(
                f"[GUI] chatting_with = "
                f"{self.gerenciador.chatting_with!r}"
            )

            self.master.title(
                f"Chat - {self.gerenciador.current_username} "
                f"(Conversando com {contact})"
            )

            # Carrega o histórico da conversa selecionada
            historico = self.gerenciador.carregar_historico_contato(contact)

            self.chat_history.config(state="normal")
            self.chat_history.delete("1.0", tk.END)
            if historico:
                self.chat_history.insert(tk.END, historico)
            self.chat_history.config(state="disabled")
            self.chat_history.see(tk.END)

    def send_message(self):
        """Envia a mensagem digitada."""
        texto = self.message_entry.get().strip()
        if texto and self.gerenciador.chatting_with:
            # Envia via gerenciador (que aplicará E2EE + Canal)
            sucesso, msg_erro = self.gerenciador.enviar_mensagem(texto)
            if sucesso:
                self.append_chat_history(f"Você: {texto}")
                self.message_entry.delete(0, tk.END)
                self.gerenciador.notificar_parou_digitando()
            else:
                messagebox.showwarning("Aviso de Segurança", msg_erro)

    def handle_key_press(self, event):
        """Notifica o evento 'digitando' ao gerenciador."""
        self.gerenciador.notificar_digitando()
        # Reagenda o "parou de digitar" se nenhuma tecla vier nos próximos 2s
        if hasattr(self, "_typing_after_id") and self._typing_after_id:
            self.master.after_cancel(self._typing_after_id)
        self._typing_after_id = self.master.after(
            2000, self.gerenciador.notificar_parou_digitando
        )

    def handle_message_received(self, sender, message):

        """Callback acionado quando uma nova mensagem chega."""
        print(f"[GUI] cb_message_received! sender={sender!r}")   # ← ADICIONE
        print(f"[GUI] cb_message_received! sender={sender!r}")
        print(
            f"[GUI] chatting_with = "
            f"{self.gerenciador.chatting_with!r}"
        )
        self.master.after(
            0, lambda: self._do_handle_message_received(sender, message)
        )
        print("[GUI] after agendado")

    def _do_handle_message_received(self, sender, message):
        print(f"[GUI] executando _do_handle! sender={sender!r}")
        if self.gerenciador.chatting_with == sender:
            print("[GUI] match! inserindo no chat_history")
            self.append_chat_history(f"{sender}: {message}")
        else:
            print(
                f"[GUI] MISMATCH: {self.gerenciador.chatting_with!r} "
                f"!= {sender!r}"
            )

    def append_chat_history(self, text):
        """Insere uma linha na caixa de texto do chat."""
        self.chat_history.config(state="normal")
        self.chat_history.insert(tk.END, text + "\n")
        self.chat_history.config(state="disabled")
        self.chat_history.see(tk.END)

    def update_contacts_list(self, contacts_with_status):
        """Atualiza a Listbox de contatos com cores de status."""
        self.master.after(
            0, lambda: self._do_update_contacts_list(contacts_with_status)
        )

    def _do_update_contacts_list(self, contacts_with_status):
        self.contacts_listbox.delete(0, tk.END)
        for entry in contacts_with_status:
            if ":" in entry:
                username, status = entry.split(":", 1)
                color = "green" if status == "online" else "black"
                self.contacts_listbox.insert(tk.END, username)
                self.contacts_listbox.itemconfig(tk.END, {"fg": color})
            else:
                self.contacts_listbox.insert(tk.END, entry)
    def update_typing_status(self, sender, is_typing):
        """Atualiza o rótulo de 'digitando...'."""
        self.master.after(
            0, lambda: self._do_update_typing_status(sender, is_typing)
        )

    def _do_update_typing_status(self, sender, is_typing):
        if self.gerenciador.chatting_with == sender:
            if is_typing:
                self.typing_label.config(
                    text=f"{sender} está digitando..."
                )
            else:
                self.typing_label.config(text="")

    def show_info(self, title, message):
        """Exibe popup informativo."""
        self.master.after(
            0, lambda: messagebox.showinfo(title, message)
        )

    def show_error(self, title, message):
        """Exibe popup de erro."""
        self.master.after(
            0, lambda: messagebox.showerror(title, message)
        )

    def on_closing(self):
        """Trata o fechamento gracioso da aplicação."""
        if messagebox.askokcancel("Sair", "Tem certeza que deseja sair?"):
            self.gerenciador.desconectar()
            self.master.destroy()



import tkinter as tk
from apresentacao.gui import ChatClientGUI
from dominio.gerenciador_chat import GerenciadorChat
from infraestrutura.rede_cliente import RedeCliente

if __name__ == "__main__":

    root = tk.Tk() 

    # Inicializa a infraestrutura de rede e o serviço de domínio 
    rede = RedeCliente()
    gerenciador = GerenciadorChat(rede)

    # Inicializa a interface gráfica passando o gerenciador     
    app = ChatClientGUI(root, gerenciador)

    root.mainloop()
from pymongo import MongoClient
import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, Scrollbar
import base64
import os
import time
import random
from tkinter import simpledialog  # Para gerar um código 2FA

# Configurações do MongoDB
uri = 'mongodb+srv://root:12345@projetobd.otpzg.mongodb.net/'
client = MongoClient(uri)
db = client['docjuridicos_']
colecao = db['hash']  # Nome da coleção alterado para 'hash'
usuarios = db['usuarios']  # Coleção para usuários

# Geração de uma chave para Fernet
def gerar_chave():
    return Fernet.generate_key()

# Função para gerar código 2FA
def gerar_codigo_2fa():
    return random.randint(100000, 999999)

# Função para cadastrar usuário
def cadastrar_usuario():
    nome_usuario = entrada_usuario_cadastro.get().strip()
    senha_usuario = entrada_senha_cadastro.get().strip()
    
    # Verifica se o usuário já existe
    if usuarios.find_one({'nome': nome_usuario}):
        messagebox.showerror("Erro", "Usuário já cadastrado.")
        return
    
    # Hash da senha
    hash_senha = hashlib.sha256(senha_usuario.encode()).hexdigest()
    
    # Armazenar o novo usuário no MongoDB
    usuarios.insert_one({'nome': nome_usuario, 'senha': hash_senha})
    messagebox.showinfo("Sucesso", "Usuário cadastrado com sucesso!")

# Função para autenticar usuário (simplificada)
def autenticar_usuario(nome_usuario, senha):
    hash_senha = hashlib.sha256(senha.encode()).hexdigest()
    usuario = usuarios.find_one({'nome': nome_usuario, 'senha': hash_senha})
    return usuario is not None

# Função para carregar e criptografar o documento
def carregar_documento():
    nome_usuario = entrada_usuario.get().strip()
    senha_usuario = entrada_senha.get().strip()
    
    if not autenticar_usuario(nome_usuario, senha_usuario):
        messagebox.showerror("Erro", "Usuário ou senha inválidos.")
        return

    # Gerar e mostrar o código 2FA
    codigo_2fa = gerar_codigo_2fa()
    messagebox.showinfo("Código 2FA", f"Código 2FA gerado: {codigo_2fa}")  # Mostrar código 2FA

    # Pede o código 2FA do usuário
    usuario_codigo = simpledialog.askinteger("Código 2FA", "Digite o código 2FA recebido:")
    
    if usuario_codigo != codigo_2fa:
        messagebox.showerror("Erro", "Código 2FA inválido!")
        return

    caminho = filedialog.askopenfilename(title="Selecionar Documento")
    if not caminho:
        return
    
    nome_cliente = entrada_cliente.get().strip()
    nome_advogado = entrada_advogado.get().strip()

    if not nome_cliente or not nome_advogado:
        messagebox.showerror("Erro", "Por favor, preencha o nome do cliente e do advogado.")
        return
    
    with open(caminho, 'rb') as f:
        conteudo = f.read()
    
    chave = gerar_chave()
    fernet = Fernet(chave)
    conteudo_criptografado = fernet.encrypt(conteudo)
    
    # Gerar hash SHA-256
    stringhash = hashlib.sha256(conteudo).hexdigest()
    
    # Armazenar no MongoDB
    documento = {
        'nome_arquivo': os.path.basename(caminho),
        'conteudo': conteudo_criptografado,
        'hash': stringhash,
        'chave': base64.urlsafe_b64encode(chave).decode(),
        'data_upload': time.time(),
        'nome_cliente': nome_cliente,
        'nome_advogado': nome_advogado,
        'usuario': nome_usuario
    }
    
    colecao.insert_one(documento)
    messagebox.showinfo("Sucesso", "Documento carregado e criptografado com sucesso!")

# Função para verificar integridade do documento
def verificar_integridade():
    nome_arquivo = entrada_nome.get().strip()
    if not nome_arquivo:
        messagebox.showerror("Erro", "Por favor, insira o nome do arquivo.")
        return
    
    documento = colecao.find_one({'nome_arquivo': nome_arquivo})
    if not documento:
        messagebox.showerror("Erro", "Documento não encontrado. Verifique o nome e tente novamente.")
        return
    
    hash_armazenado = documento['hash']
    conteudo_criptografado = documento['conteudo']
    
    # Decriptografar o conteúdo
    chave = base64.urlsafe_b64decode(documento['chave'])
    fernet = Fernet(chave)
    conteudo_decriptografado = fernet.decrypt(conteudo_criptografado)
    
    # Calcular o hash do conteúdo decriptografado
    hash_calculado = hashlib.sha256(conteudo_decriptografado).hexdigest()
    
    if hash_calculado == hash_armazenado:
        messagebox.showinfo("Integridade", "O documento não foi alterado.")
    else:
        messagebox.showerror("Integridade", "O documento foi alterado!")

# Função para compartilhar documento
def compartilhar_documento():
    nome_arquivo = entrada_nome.get().strip()
    if not nome_arquivo:
        messagebox.showerror("Erro", "Por favor, insira o nome do arquivo.")
        return
    
    documento = colecao.find_one({'nome_arquivo': nome_arquivo})
    if not documento:
        messagebox.showerror("Erro", "Documento não encontrado.")
        return

    # Gerar link temporário (exemplo simples)
    link_temporario = f"https://exemplo.com/documento/{documento['_id']}"
    
    messagebox.showinfo("Compartilhar", f"Link temporário gerado: {link_temporario}")

# Função para pesquisar documentos
def pesquisar_documento():
    nome_cliente = entrada_cliente_pesquisa.get().strip()
    nome_advogado = entrada_advogado_pesquisa.get().strip()
    nome_arquivo = entrada_nome_pesquisa.get().strip()
    
    # Filtrando os documentos por cliente, advogado ou nome do arquivo
    consulta = {}
    if nome_cliente:
        consulta['nome_cliente'] = nome_cliente
    if nome_advogado:
        consulta['nome_advogado'] = nome_advogado
    if nome_arquivo:
        consulta['nome_arquivo'] = nome_arquivo

    documentos_encontrados = colecao.find(consulta)
    
    # Limpar a lista anterior
    listbox.delete(0, tk.END)

    # Mostrar documentos encontrados
    for documento in documentos_encontrados:
        listbox.insert(tk.END, f"{documento['nome_arquivo']} (Cliente: {documento['nome_cliente']}, Advogado: {documento['nome_advogado']})")

# Função para alterar cliente ou advogado
def alterar_cliente_advogado():
    nome_arquivo = entrada_nome.get().strip()
    if not nome_arquivo:
        messagebox.showerror("Erro", "Por favor, insira o nome do arquivo.")
        return
    
    documento = colecao.find_one({'nome_arquivo': nome_arquivo})
    if not documento:
        messagebox.showerror("Erro", "Documento não encontrado.")
        return

    novo_cliente = entrada_novo_cliente.get().strip()
    novo_advogado = entrada_novo_advogado.get().strip()

    # Atualiza o cliente e advogado se fornecidos
    atualizacoes = {}
    if novo_cliente:
        atualizacoes['nome_cliente'] = novo_cliente
    if novo_advogado:
        atualizacoes['nome_advogado'] = novo_advogado

    colecao.update_one({'nome_arquivo': nome_arquivo}, {'$set': atualizacoes})

    messagebox.showinfo("Sucesso", "Cliente e/ou advogado alterado com sucesso!")

# Configuração da interface Tkinter
root = tk.Tk()
root.title("Plataforma de Armazenamento de Documentos Jurídicos")

# Configuração do Canvas e da Scrollbar
canvas = tk.Canvas(root)
scrollbar = Scrollbar(root, orient="vertical", command=canvas.yview)
scrollable_frame = tk.Frame(canvas)

scrollable_frame.bind(
    "<Configure>",
    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
)

canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

# Adiciona a scrollbar ao canvas
canvas.configure(yscrollcommand=scrollbar.set)

# Layout
scrollbar.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

# Frame para organização dos widgets
frame = scrollable_frame

# Entradas para cadastro
tk.Label(frame, text="Cadastro de Usuário").grid(row=0, columnspan=2)

tk.Label(frame, text="Usuário:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
entrada_usuario_cadastro = tk.Entry(frame, width=50)
entrada_usuario_cadastro.grid(row=1, column=1, padx=5, pady=5)

tk.Label(frame, text="Senha:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
entrada_senha_cadastro = tk.Entry(frame, show="*")
entrada_senha_cadastro.grid(row=2, column=1, padx=5, pady=5)

# Botão para cadastrar
btn_cadastrar = tk.Button(frame, text="Cadastrar", command=cadastrar_usuario, bg="lightgreen")
btn_cadastrar.grid(row=3, columnspan=2, pady=10)

# Entradas para autenticação
tk.Label(frame, text="Autenticação").grid(row=4, columnspan=2)

tk.Label(frame, text="Cliente:").grid(row=5, column=0, padx=5, pady=5, sticky="e")
entrada_cliente = tk.Entry(frame, width=50)
entrada_cliente.grid(row=5, column=1, padx=5, pady=5)

tk.Label(frame, text="Advogado:").grid(row=6, column=0, padx=5, pady=5, sticky="e")
entrada_advogado = tk.Entry(frame, width=50)
entrada_advogado.grid(row=6, column=1, padx=5, pady=5)

tk.Label(frame, text="Usuário:").grid(row=7, column=0, padx=5, pady=5, sticky="e")
entrada_usuario = tk.Entry(frame, width=50)
entrada_usuario.grid(row=7, column=1, padx=5, pady=5)

tk.Label(frame, text="Senha:").grid(row=8, column=0, padx=5, pady=5, sticky="e")
entrada_senha = tk.Entry(frame, show="*")
entrada_senha.grid(row=8, column=1, padx=5, pady=5)

# Botão para carregar documento
btn_carregar = tk.Button(frame, text="Carregar Documento", command=carregar_documento, bg="lightgreen")
btn_carregar.grid(row=9, columnspan=2, pady=10)

# Entradas para verificar integridade
tk.Label(frame, text="Verificar Integridade").grid(row=10, columnspan=2)

tk.Label(frame, text="Nome do Arquivo:").grid(row=11, column=0, padx=5, pady=5, sticky="e")
entrada_nome = tk.Entry(frame, width=50)
entrada_nome.grid(row=11, column=1, padx=5, pady=5)

# Botão para verificar integridade
btn_verificar = tk.Button(frame, text="Verificar", command=verificar_integridade, bg="lightyellow")
btn_verificar.grid(row=12, columnspan=2, pady=10)

# Entradas para compartilhar documento
tk.Label(frame, text="Compartilhar Documento").grid(row=13, columnspan=2)

# Botão para compartilhar documento
btn_compartilhar = tk.Button(frame, text="Compartilhar", command=compartilhar_documento, bg="lightcoral")
btn_compartilhar.grid(row=14, columnspan=2, pady=10)

# Entradas para pesquisa
tk.Label(frame, text="Pesquisar Documentos").grid(row=15, columnspan=2)

tk.Label(frame, text="Cliente:").grid(row=16, column=0, padx=5, pady=5, sticky="e")
entrada_cliente_pesquisa = tk.Entry(frame, width=50)
entrada_cliente_pesquisa.grid(row=16, column=1, padx=5, pady=5)

tk.Label(frame, text="Advogado:").grid(row=17, column=0, padx=5, pady=5, sticky="e")
entrada_advogado_pesquisa = tk.Entry(frame, width=50)
entrada_advogado_pesquisa.grid(row=17, column=1, padx=5, pady=5)

tk.Label(frame, text="Nome do Arquivo:").grid(row=18, column=0, padx=5, pady=5, sticky="e")
entrada_nome_pesquisa = tk.Entry(frame, width=50)
entrada_nome_pesquisa.grid(row=18, column=1, padx=5, pady=5)

btn_pesquisar = tk.Button(frame, text="Pesquisar", command=pesquisar_documento, bg="lightblue")
btn_pesquisar.grid(row=19, columnspan=2, pady=10)

listbox = Listbox(frame, width=75, height=10)
listbox.grid(row=20, columnspan=2, pady=10)

scrollbar_listbox = Scrollbar(frame)
scrollbar_listbox.grid(row=20, column=2, sticky="ns")
listbox.config(yscrollcommand=scrollbar_listbox.set)
scrollbar_listbox.config(command=listbox.yview)

tk.Label(frame, text="Alterar Cliente ou Advogado").grid(row=21, columnspan=2)

tk.Label(frame, text="Nome do Arquivo:").grid(row=22, column=0, padx=5, pady=5, sticky="e")
entrada_nome_alterar = tk.Entry(frame, width=50)
entrada_nome_alterar.grid(row=22, column=1, padx=5, pady=5)

tk.Label(frame, text="Novo Cliente:").grid(row=23, column=0, padx=5, pady=5, sticky="e")
entrada_novo_cliente = tk.Entry(frame, width=50)
entrada_novo_cliente.grid(row=23, column=1, padx=5, pady=5)

tk.Label(frame, text="Novo Advogado:").grid(row=24, column=0, padx=5, pady=5, sticky="e")
entrada_novo_advogado = tk.Entry(frame, width=50)
entrada_novo_advogado.grid(row=24, column=1, padx=5, pady=5)

btn_alterar = tk.Button(frame, text="Alterar", command=alterar_cliente_advogado, bg="lightgreen")
btn_alterar.grid(row=25, columnspan=2, pady=10)

root.mainloop()

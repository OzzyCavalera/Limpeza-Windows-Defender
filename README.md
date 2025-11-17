# 🛡️ Limpeza do Windows Defender

Ferramenta avançada de limpeza do Windows Defender com interface gráfica moderna e intuitiva.

## 📋 Descrição

Aplicação em PowerShell que permite limpar de forma segura e eficiente os ficheiros temporários, histórico, logs e caches do Windows Defender, libertando espaço em disco e otimizando o desempenho do sistema.

## ✨ Características

- 🎨 **Interface Gráfica Moderna** - Design profissional com gradientes e elementos visuais atraentes
- 🔒 **Modo Seguro** - Proteção contra operações que possam corromper o Defender
- 📊 **Limpeza Seletiva** - Escolha exatamente o que pretende limpar
- 📈 **Progresso em Tempo Real** - Barra de progresso e feedback detalhado
- 🔄 **Reinício Automático** - Opções para reiniciar em Modo Seguro ou Normal
- 📝 **Registo Detalhado** - Logs completos de todas as operações realizadas
- ⚡ **Otimizado** - Código otimizado para máxima eficiência

## 🧹 Opções de Limpeza

### Modo Normal
- ✅ **Quarentena** - Remove ficheiros em quarentena (pode libertar vários GB)
- ✅ **Backups** - Elimina cópias de segurança de definições antigas
- ✅ **Histórico** - Limpa histórico de verificações e deteções
- ✅ **Logs** - Remove ficheiros de registo antigos
- ✅ **Temporários** - Limpa ficheiros de cache temporários
- 🔓 **Assinaturas Antigas** - Remove cache de assinaturas de vírus desatualizadas
- 🔓 **Exclusões do Utilizador** - Remove TODAS as exclusões configuradas (irreversível)

### Modo Seguro
- ✅ Todas as opções básicas (Quarentena, Backups, Histórico, Logs, Temporários)
- ❌ Assinaturas Antigas (desativado por segurança)
- ❌ Exclusões do Utilizador (desativado por segurança)

## 💻 Requisitos

- Windows 10 / 11 / LTSC
- PowerShell 5.1 ou superior
- Privilégios de Administrador
- Windows Defender instalado e ativo

## 🚀 Utilização

### Método 1: Executar Diretamente
```powershell
# Abrir PowerShell como Administrador
powershell.exe -ExecutionPolicy Bypass -File "Limpeza-Windows-Defender.ps1"
```

### Método 2: Modo Silencioso
```powershell
# Limpar tudo sem interface gráfica
powershell.exe -ExecutionPolicy Bypass -File "Limpeza-Windows-Defender.ps1" -CleanAll -Quiet
```

### Método 3: Modo Seguro
```powershell
# Executar em modo seguro (sem GUI)
powershell.exe -ExecutionPolicy Bypass -File "Limpeza-Windows-Defender.ps1" -SafeMode
```

## 📦 Compilação para EXE

Para criar um executável standalone:

```powershell
# Instalar ps2exe
Install-Module -Name ps2exe -Scope CurrentUser -Force

# Compilar o script
Invoke-PS2EXE -inputFile "Limpeza-Windows-Defender.ps1" -outputFile "LimpezaDefender.exe" -iconFile "icon.ico" -noConsole
```

## ⚙️ Parâmetros Disponíveis

| Parâmetro | Tipo | Descrição |
|-----------|------|--------|
| `-SafeMode` | Switch | Ativa modo seguro sem interface gráfica |
| `-Quiet` | Switch | Execução silenciosa sem prompts |
| `-CleanAll` | Switch | Limpa todos os itens automaticamente |
| `-LogPath` | String | Caminho personalizado para o ficheiro de log |

## 🔧 Funcionalidades Avançadas

### Gestão de Permissões
- Toma posse automática de ficheiros protegidos
- Altera proprietário para Administradores quando necessário
- Gere permissões de forma segura e reversível

### Reinício do Sistema
- **Modo Seguro Mínimo** - Para limpeza mais profunda
- **Modo Normal** - Retorna ao modo normal após limpeza
- Validação e retry automático em caso de falha

### Logs e Auditoria
- Registo detalhado de todas as operações
- Timestamps precisos em cada entrada
- Níveis de severidade (INFO, WARNING, ERROR, SUCCESS)
- Fallback automático se o log principal falhar

## 📊 Espaço Libertado

A quantidade de espaço libertado varia consoante:
- Tempo desde a última limpeza
- Frequência de verificações do Defender
- Número de ficheiros em quarentena
- Histórico de deteções

**Valores típicos**: 500 MB - 5 GB

## ⚠️ Avisos Importantes

1. **Sempre execute como Administrador** - Obrigatório para aceder aos ficheiros do Defender
2. **Exclusões são permanentes** - A remoção de exclusões não pode ser desfeita
3. **Backup recomendado** - Considere criar um ponto de restauro antes
4. **Modo Seguro é mais eficaz** - Algumas limpezas requerem Modo Seguro

## 🐛 Resolução de Problemas

### "Acesso Negado"
- Certifique-se de que está a executar como Administrador
- Tente executar em Modo Seguro

### "Windows Defender não encontrado"
- Verifique se o Windows Defender está instalado
- Confirme que o serviço WinDefend está ativo

### Script não executa
- Altere a política de execução: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process`

## 📜 Licença

Este projeto está licenciado sob os termos que o autor definir.

## 👤 Autor

**Ozzy Cavalera**
- GitHub: [@OzzyCavalera](https://github.com/OzzyCavalera)

## 🤝 Contribuições

Contribuições, issues e pedidos de funcionalidades são bem-vindos!

## ⭐ Apoio

Se este projeto foi útil, considera dar uma estrela ⭐

---

**Versão**: 6.6.6  
**Última atualização**: 2025  
**Compatibilidade**: Windows 10/11/LTSC

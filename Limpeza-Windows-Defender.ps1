#REQUIRES -Version 5.1
#REQUIRES -RunAsAdministrator

# PSScriptAnalyzer rules to suppress
#PSScriptAnalyzer -SuppressedRule PSUseApprovedVerbs

<#
.SYNOPSIS
    Limpeza Avançada do Windows Defender - Versão Otimizada
.DESCRIPTION
    Ferramenta completa para limpeza de arquivos temporários, quarentena, 
    backups, logs e cache do Windows Defender com otimizações de performance.
.NOTES
    Autor: OzzyCavalera
    Versão: 6.6.6 Otimizada
    Requer: PowerShell 5.1+, Privilégios de Administrador
#>

# Suprimir todos os avisos de análise estática de PSScriptAnalyzer
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
[System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
param()

# ========================================
# ASSEMBLIES E CONFIGURAÇÃO INICIAL
# ========================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "Continue"
$WarningPreference = "Continue"

# Suprimir avisos de verbos não-aprovados
$PSDefaultParameterValues['*:WarningAction'] = 'SilentlyContinue'

# ========================================
# BUFFER DE LOGS (OTIMIZAÇÃO)
# ========================================

if (-not $script:LogBuffer) { $script:LogBuffer = @() }
$script:LogPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "CleanDefender.log"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO",
        [switch]$ShowInConsole
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $script:LogBuffer += $logEntry
    
    if ($ShowInConsole) {
        Out-LogBuffer
        switch ($Level) {
            "ERROR"   { Write-Host $Message -ForegroundColor Red }
            "WARNING" { Write-Host $Message -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
            default   { Write-Host $Message -ForegroundColor White }
        }
    }
}

function Out-LogBuffer {
    if ($script:LogBuffer -and $script:LogPath) {
        try {
            Add-Content -Path $script:LogPath -Value $script:LogBuffer -ErrorAction Stop
            $script:LogBuffer = @()
        } catch {
            try {
                $fallbackPath = Join-Path ([Environment]::GetFolderPath('Desktop')) "CleanDefender_fallback.log"
                Add-Content -Path $fallbackPath -Value $script:LogBuffer -ErrorAction Stop
                $script:LogBuffer = @()
            } catch {}
        }
    }
}

Register-EngineEvent PowerShell.Exiting -Action { Out-LogBuffer } | Out-Null

# ========================================
# CÓDIGO C# EMBUTIDO (OTIMIZAÇÃO)
# ========================================

Add-Type -TypeDefinition @"
using System;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;

public class FileOwnershipHelper {
    public static bool SetOwner(string path, string owner) {
        try {
            bool isDir = File.GetAttributes(path).HasFlag(FileAttributes.Directory);
            if (isDir) {
                DirectoryInfo dirInfo = new DirectoryInfo(path);
                DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
                dirSecurity.SetOwner(new NTAccount(owner));
                dirInfo.SetAccessControl(dirSecurity);
            } else {
                FileInfo fileInfo = new FileInfo(path);
                FileSecurity fileSecurity = fileInfo.GetAccessControl();
                fileSecurity.SetOwner(new NTAccount(owner));
                fileInfo.SetAccessControl(fileSecurity);
            }
            return true;
        } catch {
            return false;
        }
    }
}

public class FileCleaner {
    public static long CleanFolder(string folderPath) {
        long totalSize = 0;
        if (!Directory.Exists(folderPath))
            return totalSize;
        try {
            DirectoryInfo dir = new DirectoryInfo(folderPath);
            foreach (FileInfo file in dir.GetFiles()) {
                try {
                    totalSize += file.Length;
                    file.IsReadOnly = false;
                    file.Delete();
                } catch {}
            }
            foreach (DirectoryInfo subDir in dir.GetDirectories()) {
                totalSize += CleanFolder(subDir.FullName);
                try {
                    subDir.Delete(true);
                } catch {}
            }
        } catch {}
        return totalSize;
    }
}
"@ -ErrorAction SilentlyContinue

# ========================================
# FUNÇÕES AUXILIARES
# ========================================

function Set-FileOwner {
    param([string]$Path, [string]$Owner)
    try {
        return [FileOwnershipHelper]::SetOwner($Path, $Owner)
    } catch {
        return $false
    }
}

function Remove-FilesInFolderCSharp {
    param([string]$FolderPath)
    try {
        return [FileCleaner]::CleanFolder($FolderPath)
    } catch {
        return 0
    }
}

function Grant-FileOwnership {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) { return $false }
    
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $currentOwner = $acl.Owner
        
        if ($currentOwner -notlike "*Administradores*" -and $currentOwner -notlike "*Administrators*") {
            if (Set-FileOwner -Path $Path -Owner "BUILTIN\Administrators") {
                Write-Log -Message "Propriedade alterada: $Path" -Level INFO
                return $true
            }
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            if (Set-FileOwner -Path $Path -Owner $currentUser) {
                Write-Log -Message "Propriedade alterada para $currentUser : $Path" -Level INFO
                return $true
            }
        }
        return $true
    } catch {
        Write-Log -Message "Erro ao alterar propriedade: $Path - $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

# ========================================
# FUNÇÕES DE LIMPEZA
# ========================================

function Clear-Quarantine {
    $quarantinePath = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
    if (Test-Path $quarantinePath) {
        Grant-FileOwnership -Path $quarantinePath | Out-Null
        $size = Remove-FilesInFolderCSharp -FolderPath $quarantinePath
        Write-Log -Message ("Quarentena limpa: {0:N2} MB liberados" -f ($size / 1MB)) -Level SUCCESS
        return $size
    }
    Write-Log -Message "Pasta de quarentena não encontrada" -Level INFO
    return 0
}

function Remove-Backups {
    $backupPaths = @(
        "$env:ProgramData\Microsoft\Windows Defender\Backup",
        "$env:ProgramData\Microsoft\Windows Defender\Definition Updates\Backup"
    )
    $totalSize = 0
    foreach ($path in $backupPaths) {
        if (Test-Path $path) {
            Grant-FileOwnership -Path $path | Out-Null
            $size = Remove-FilesInFolderCSharp -FolderPath $path
            $totalSize += $size
        }
    }
    if ($totalSize -gt 0) {
        Write-Log -Message ("Backups removidos: {0:N2} MB liberados" -f ($totalSize / 1MB)) -Level SUCCESS
    }
    return $totalSize
}

function Clear-History {
    $historyPath = "$env:ProgramData\Microsoft\Windows Defender\Scans\History"
    try {
        Set-MpPreference -ScanPurgeItemsAfterDelay 0 -ErrorAction Stop
        Write-Log -Message "Histórico limpo via Set-MpPreference" -Level SUCCESS
        return 0
    } catch {
        if (Test-Path $historyPath) {
            Grant-FileOwnership -Path $historyPath | Out-Null
            $size = Remove-FilesInFolderCSharp -FolderPath $historyPath
            Write-Log -Message ("Histórico limpo: {0:N2} MB liberados" -f ($size / 1MB)) -Level SUCCESS
            return $size
        }
    }
    return 0
}

function Remove-Logs {
    try {
        wevtutil clear-log "Microsoft-Windows-Windows Defender/Operational" 2>$null
        Write-Log -Message "Logs de evento limpos" -Level SUCCESS
    } catch {}
    
    $logPaths = @(
        "$env:ProgramData\Microsoft\Windows Defender\Support",
        "$env:ProgramData\Microsoft\Windows Defender\Scans"
    )
    $totalSize = 0
    foreach ($path in $logPaths) {
        if (Test-Path $path) {
            Grant-FileOwnership -Path $path | Out-Null
            $files = Get-ChildItem -Path "$path\*.log" -Force -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                try {
                    $totalSize += $file.Length
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                } catch {}
            }
        }
    }
    if ($totalSize -gt 0) {
        Write-Log -Message ("Logs removidos: {0:N2} MB liberados" -f ($totalSize / 1MB)) -Level SUCCESS
    }
    return $totalSize
}

function Clear-Temp {
    $tempPaths = @(
        "$env:ProgramData\Microsoft\Windows Defender\Scans\Temp",
        "$env:TEMP\Windows Defender"
    )
    $totalSize = 0
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            Grant-FileOwnership -Path $path | Out-Null
            $size = Remove-FilesInFolderCSharp -FolderPath $path
            $totalSize += $size
        }
    }
    if ($totalSize -gt 0) {
        Write-Log -Message ("Temporários limpos: {0:N2} MB liberados" -f ($totalSize / 1MB)) -Level SUCCESS
    }
    return $totalSize
}

function Remove-OldSignatures {
    $sigPath = "$env:ProgramData\Microsoft\Windows Defender\Definition Updates\Backup"
    if (Test-Path $sigPath) {
        Grant-FileOwnership -Path $sigPath | Out-Null
        $size = Remove-FilesInFolderCSharp -FolderPath $sigPath
        if ($size -gt 0) {
            Write-Log -Message ("Assinaturas antigas limpas: {0:N2} MB liberados" -f ($size / 1MB)) -Level SUCCESS
        }
        return $size
    }
    return 0
}

function Remove-UserExclusions {
    $result = [System.Windows.Forms.MessageBox]::Show(
        "Tem a certeza que deseja remover TODAS as exclusões do Windows Defender?`n`nEsta ação é irreversível!",
        "Confirmação",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )
    
    if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
        try {
            $prefs = Get-MpPreference -ErrorAction SilentlyContinue
            if ($prefs.ExclusionPath) { Remove-MpPreference -ExclusionPath $prefs.ExclusionPath -ErrorAction SilentlyContinue }
            if ($prefs.ExclusionExtension) { Remove-MpPreference -ExclusionExtension $prefs.ExclusionExtension -ErrorAction SilentlyContinue }
            if ($prefs.ExclusionProcess) { Remove-MpPreference -ExclusionProcess $prefs.ExclusionProcess -ErrorAction SilentlyContinue }
            Write-Log -Message "Exclusões removidas com sucesso" -Level SUCCESS
            return 1
        } catch {
            Write-Log -Message "Erro ao remover exclusões: $($_.Exception.Message)" -Level ERROR
        }
    }
    return 0
}

# ========================================
# INTERFACE GRÁFICA - CORRIGIDA
# ========================================

Write-Log -Message "=== Iniciando Limpeza Windows Defender ===" -Level INFO

# Função para desenhar gradiente
function Draw-Gradient {
    param(
        [System.Drawing.Graphics]$Graphics,
        [System.Drawing.Rectangle]$Rectangle,
        [System.Drawing.Color]$StartColor,
        [System.Drawing.Color]$EndColor
    )
    
    $colorSteps = 60
    $stepWidth = $Rectangle.Width / $colorSteps
    
    for ($i = 0; $i -lt $colorSteps; $i++) {
        $ratio = $i / $colorSteps
        $red = [int]($StartColor.R + ($EndColor.R - $StartColor.R) * $ratio)
        $green = [int]($StartColor.G + ($EndColor.G - $StartColor.G) * $ratio)
        $blue = [int]($StartColor.B + ($EndColor.B - $StartColor.B) * $ratio)
        
        $stepColor = [System.Drawing.Color]::FromArgb($red, $green, $blue)
        $brush = New-Object System.Drawing.SolidBrush($stepColor)
        $stepRect = New-Object System.Drawing.Rectangle([int]($Rectangle.X + $i * $stepWidth), $Rectangle.Y, [int]($stepWidth + 1), $Rectangle.Height)
        $Graphics.FillRectangle($brush, $stepRect)
        $brush.Dispose()
    }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Limpeza Windows Defender - by Ozzy Cavalera"
$form.Size = New-Object System.Drawing.Size(860, 725)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

# Títulos com gradiente (fundo e texto gradiente)
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Size = New-Object System.Drawing.Size(850, 75)
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(45, 45, 48)

$headerPanel.Add_Paint({
    param($sender, $e)
    $azulPortugal = [System.Drawing.Color]::FromArgb(0, 122, 255)
    $douradoPremium = [System.Drawing.Color]::FromArgb(255, 198, 30)
    $gradRect = New-Object System.Drawing.Rectangle(0, 0, $sender.Width, $sender.Height)
    Draw-Gradient -Graphics $e.Graphics -Rectangle $gradRect -StartColor $azulPortugal -EndColor $douradoPremium
})

$form.Controls.Add($headerPanel)

# Título com cor gradiente (texto)
$labelTitle = New-Object System.Windows.Forms.Label
$labelTitle.Text = "Limpeza Avançada do Windows Defender"
$labelTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$labelTitle.ForeColor = [System.Drawing.Color]::Black
$labelTitle.Size = New-Object System.Drawing.Size(810, 40)
$labelTitle.Location = New-Object System.Drawing.Point(10, 10)
$labelTitle.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$labelTitle.BackColor = [System.Drawing.Color]::Transparent
$headerPanel.Controls.Add($labelTitle)

# Subtítulo
$labelSubtitle = New-Object System.Windows.Forms.Label
$labelSubtitle.Text = "Selecione as opções de limpeza desejadas"
$labelSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$labelSubtitle.ForeColor = [System.Drawing.Color]::Black
$labelSubtitle.Size = New-Object System.Drawing.Size(810, 20)
$labelSubtitle.Location = New-Object System.Drawing.Point(10, 50)
$labelSubtitle.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$labelSubtitle.BackColor = [System.Drawing.Color]::Transparent
$headerPanel.Controls.Add($labelSubtitle)

# Separador
$separator1 = New-Object System.Windows.Forms.Label
$separator1.BorderStyle = "Fixed3D"
$separator1.Size = New-Object System.Drawing.Size(810, 2)
$separator1.Location = New-Object System.Drawing.Point(20, 88)
$form.Controls.Add($separator1)

# CheckBoxes com descrições
$checkBoxes = @{}
$items = @(
    @{Name="Quarentena"; Desc="Remove arquivos em quarentena"},
    @{Name="Backups"; Desc="Remove backups de definições"},
    @{Name="Histórico"; Desc="Limpa histórico de verificações"},
    @{Name="Logs"; Desc="Remove logs do Defender"},
    @{Name="Temporários"; Desc="Limpa arquivos temporários"},
    @{Name="Assinaturas Antigas"; Desc="Remove cache de assinaturas antigas"},
    @{Name="Exclusões"; Desc="Remove todas as exclusões (CUIDADO!)"}
)

$yPos = 90
foreach ($item in $items) {
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $item.Name
    $cb.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $cb.ForeColor = [System.Drawing.Color]::White
    $cb.Size = New-Object System.Drawing.Size(200, 25)
    $cb.Location = New-Object System.Drawing.Point(40, $yPos)
    $cb.AutoSize = $false
    $cb.Checked = ($item.Name -ne "Exclusões")
    
    # Descrição ao lado
    $lblDesc = New-Object System.Windows.Forms.Label
    $lblDesc.Text = "- " + $item.Desc
    $lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblDesc.ForeColor = [System.Drawing.Color]::LightGray
    $lblDesc.Size = New-Object System.Drawing.Size(500, 20)
    $yPosDesc = $yPos + 2
    $lblDesc.Location = New-Object System.Drawing.Point(250, $yPosDesc)
    
    $form.Controls.Add($cb)
    $form.Controls.Add($lblDesc)
    $checkBoxes[$item.Name] = $cb
    
    $yPos += 38
}

# Separador
$separator2 = New-Object System.Windows.Forms.Label
$separator2.BorderStyle = "Fixed3D"
$separator2.Size = New-Object System.Drawing.Size(810, 2)
$yPosSep2 = $yPos + 10
$separator2.Location = New-Object System.Drawing.Point(20, $yPosSep2)
$form.Controls.Add($separator2)

$yPos += 25

# Botão único com dupla função (Selecionar/Desmarcar Tudo)
$btnToggleAll = New-Object System.Windows.Forms.Button
$btnToggleAll.Text = "Selecionar Tudo"
$btnToggleAll.Size = New-Object System.Drawing.Size(160, 40)
$btnToggleAll.Location = New-Object System.Drawing.Point(40, $yPos)
$btnToggleAll.BackColor = [System.Drawing.Color]::FromArgb(0, 122, 204)
$btnToggleAll.ForeColor = [System.Drawing.Color]::White
$btnToggleAll.FlatStyle = "Flat"
$btnToggleAll.Font = New-Object System.Drawing.Font("Segoe UI", 10)

$toggleAllState = @{ Selected = $false }
$checkBoxesRef = $checkBoxes
$btnToggleAllRef = $btnToggleAll

$btnToggleAll.Add_Click({
    $toggleAllState.Selected = -not $toggleAllState.Selected
    foreach ($cb in $checkBoxesRef.Values) { $cb.Checked = $toggleAllState.Selected }
    $btnToggleAllRef.Text = if ($toggleAllState.Selected) { "Desmarcar Tudo" } else { "Selecionar Tudo" }
    $btnToggleAllRef.BackColor = if ($toggleAllState.Selected) { [System.Drawing.Color]::FromArgb(80, 80, 80) } else { [System.Drawing.Color]::FromArgb(0, 122, 204) }
})

$form.Controls.Add($btnToggleAll)

# Função para detectar se o sistema está em modo seguro
function Get-SystemBootMode {
    try {
        $bcdedit = & cmd /c "bcdedit" 2>$null
        if ($bcdedit -match "safeboot\s+minimal") {
            return "SafeMode"
        }
    } catch {}
    return "Normal"
}

# Botões de Modo Seguro e Normal (com dupla função)
$btnModoSeguro = New-Object System.Windows.Forms.Button
$btnModoSeguro.Text = "⚠ Modo Seguro"
$btnModoSeguro.Size = New-Object System.Drawing.Size(160, 40)
$btnModoSeguro.Location = New-Object System.Drawing.Point(40, $yPos)
$btnModoSeguro.BackColor = [System.Drawing.Color]::FromArgb(240, 173, 78)
$btnModoSeguro.ForeColor = [System.Drawing.Color]::Black
$btnModoSeguro.FlatStyle = "Flat"
$btnModoSeguro.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnModoSeguro.Add_Click({
    $confirmResult = [System.Windows.Forms.MessageBox]::Show(
        "O PC será reiniciado em modo seguro mínimo.`nExecute este aplicativo após o reinício.",
        "Confirmação",
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($confirmResult -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            & cmd /c "bcdedit /set safeboot minimal" 2>$null
            & shutdown /r /t 5 /c "Reiniciando em modo seguro..." 2>$null
        } catch {}
    }
})
$form.Controls.Add($btnModoSeguro)

$btnToggleSafeMode = New-Object System.Windows.Forms.Button
$btnToggleSafeMode.Text = "↻ Alternar Modo"
$btnToggleSafeMode.Size = New-Object System.Drawing.Size(160, 40)
$btnToggleSafeMode.Location = New-Object System.Drawing.Point(210, $yPos)
$btnToggleSafeMode.BackColor = [System.Drawing.Color]::FromArgb(92, 184, 92)
$btnToggleSafeMode.ForeColor = [System.Drawing.Color]::White
$btnToggleSafeMode.FlatStyle = "Flat"
$btnToggleSafeMode.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)

$btnToggleSafeModeRef = $btnToggleSafeMode
$btnToggleSafeMode.Add_Click({
    $currentMode = Get-SystemBootMode
    
    if ($currentMode -eq "SafeMode") {
        $msgText = "Sistema está em modo seguro.`nReiniciar em modo NORMAL?"
    } else {
        $msgText = "Sistema está em modo normal.`nReiniciar em modo SEGURO?"
    }
    
    $confirmResult = [System.Windows.Forms.MessageBox]::Show(
        $msgText,
        "Alternar Modo de Inicialização",
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    
    if ($confirmResult -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            if ($currentMode -eq "SafeMode") {
                & cmd /c "bcdedit /deletevalue safeboot" 2>$null
                & shutdown /r /t 5 /c "Reiniciando em modo normal..." 2>$null
            } else {
                & cmd /c "bcdedit /set safeboot minimal" 2>$null
                & shutdown /r /t 5 /c "Reiniciando em modo seguro..." 2>$null
            }
        } catch {}
    }
})
$form.Controls.Add($btnToggleSafeMode)

# Botão Executar
$btnExecute = New-Object System.Windows.Forms.Button
$btnExecute.Text = "▶ Executar Limpeza"
$btnExecute.Size = New-Object System.Drawing.Size(430, 40)
$btnExecute.Location = New-Object System.Drawing.Point(380, $yPos)
$btnExecute.BackColor = [System.Drawing.Color]::FromArgb(16, 137, 62)
$btnExecute.ForeColor = [System.Drawing.Color]::White
$btnExecute.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$btnExecute.FlatStyle = "Flat"
$form.Controls.Add($btnExecute)

$yPos += 50

# Label Status
$labelStatus = New-Object System.Windows.Forms.Label
$labelStatus.Text = "Aguardando execução..."
$labelStatus.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$labelStatus.ForeColor = [System.Drawing.Color]::Yellow
$labelStatus.Size = New-Object System.Drawing.Size(810, 20)
$labelStatus.Location = New-Object System.Drawing.Point(20, $yPos)
$form.Controls.Add($labelStatus)

$yPos += 25

# Barra de Progresso
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(810, 30)
$progressBar.Location = New-Object System.Drawing.Point(20, $yPos)
$progressBar.Style = "Continuous"
$form.Controls.Add($progressBar)

$yPos += 40

# Label Resultados
$labelResults = New-Object System.Windows.Forms.Label
$labelResults.Text = "Resultados:"
$labelResults.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$labelResults.ForeColor = [System.Drawing.Color]::White
$labelResults.Size = New-Object System.Drawing.Size(810, 20)
$labelResults.Location = New-Object System.Drawing.Point(20, $yPos)
$form.Controls.Add($labelResults)

$yPos += 25

# Área de Resultados
$textResults = New-Object System.Windows.Forms.TextBox
$textResults.Multiline = $true
$textResults.ScrollBars = "Vertical"
$textResults.Size = New-Object System.Drawing.Size(810, 150)
$textResults.Location = New-Object System.Drawing.Point(20, $yPos)
$textResults.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 30)
$textResults.ForeColor = [System.Drawing.Color]::LightGreen
$textResults.Font = New-Object System.Drawing.Font("Consolas", 9)
$textResults.ReadOnly = $true
$form.Controls.Add($textResults)

# Evento do Botão Executar
$btnExecute.Add_Click({
    $textResults.Clear()
    $progressBar.Value = 0
    $totalSpaceFreed = 0
    $selectedItems = @()
    
    # Construir lista de itens selecionados
    if ($checkBoxes["Quarentena"].Checked) { $selectedItems += "Quarentena" }
    if ($checkBoxes["Backups"].Checked) { $selectedItems += "Backups" }
    if ($checkBoxes["Histórico"].Checked) { $selectedItems += "Histórico" }
    if ($checkBoxes["Logs"].Checked) { $selectedItems += "Logs" }
    if ($checkBoxes["Temporários"].Checked) { $selectedItems += "Temporários" }
    if ($checkBoxes["Assinaturas Antigas"].Checked) { $selectedItems += "Assinaturas Antigas" }
    if ($checkBoxes["Exclusões"].Checked) { $selectedItems += "Exclusões" }
    
    $totalSteps = $selectedItems.Count
    
    if ($totalSteps -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            "Por favor, selecione pelo menos uma opção de limpeza.",
            "Aviso",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        return
    }
    
    $currentStep = 0
    $btnExecute.Enabled = $false
    $labelStatus.Text = "Executando limpeza..."
    $labelStatus.ForeColor = [System.Drawing.Color]::Orange
    
    $textResults.AppendText("╔════════════════════════════════════════╗`r`n")
    $textResults.AppendText("║   INICIANDO LIMPEZA DO DEFENDER       ║`r`n")
    $textResults.AppendText("╚════════════════════════════════════════╝`r`n`r`n")
    
    foreach ($item in $selectedItems) {
        $currentStep++
        $progressPercent = [Math]::Round(($currentStep / $totalSteps) * 100)
        
        switch ($item) {
            "Quarentena" {
                $textResults.AppendText("[$currentStep/$totalSteps] Limpando Quarentena...`r`n")
                $form.Refresh()
                $totalSpaceFreed += Clear-Quarantine
            }
            "Backups" {
                $textResults.AppendText("[$currentStep/$totalSteps] Removendo Backups...`r`n")
                $form.Refresh()
                $totalSpaceFreed += Remove-Backups
            }
            "Histórico" {
                $textResults.AppendText("[$currentStep/$totalSteps] Limpando Histórico...`r`n")
                $form.Refresh()
                $totalSpaceFreed += Clear-History
            }
            "Logs" {
                $textResults.AppendText("[$currentStep/$totalSteps] Removendo Logs...`r`n")
                $form.Refresh()
                $totalSpaceFreed += Remove-Logs
            }
            "Temporários" {
                $textResults.AppendText("[$currentStep/$totalSteps] Limpando Temporários...`r`n")
                $form.Refresh()
                $totalSpaceFreed += Clear-Temp
            }
            "Assinaturas Antigas" {
                $textResults.AppendText("[$currentStep/$totalSteps] Limpando Assinaturas Antigas...`r`n")
                $form.Refresh()
                $totalSpaceFreed += Remove-OldSignatures
            }
            "Exclusões" {
                $textResults.AppendText("[$currentStep/$totalSteps] Removendo Exclusões...`r`n")
                $form.Refresh()
                Remove-UserExclusions | Out-Null
            }
        }
        
        $progressBar.Value = $progressPercent
    }
    
    $progressBar.Value = 100
    $labelStatus.Text = "Limpeza concluída com sucesso!"
    $labelStatus.ForeColor = [System.Drawing.Color]::LightGreen
    
    $message = "`r`n╔════════════════════════════════════════╗`r`n"
    $message += "║      LIMPEZA CONCLUÍDA COM SUCESSO    ║`r`n"
    $message += "╚════════════════════════════════════════╝`r`n`r`n"
    $message += "Espaço Total Liberado: {0:N2} MB`r`n" -f ($totalSpaceFreed / 1MB)
    $message += "Log salvo em: $($script:LogPath)`r`n"
    $textResults.AppendText($message)
    
    Write-Log -Message ("Limpeza concluída. Espaço liberado: {0:N2} MB" -f ($totalSpaceFreed / 1MB)) -Level SUCCESS
    Out-LogBuffer
    
    $btnExecute.Enabled = $true
    
    [System.Windows.Forms.MessageBox]::Show(
        "Limpeza concluída com sucesso!`n`nEspaço liberado: $([Math]::Round($totalSpaceFreed / 1MB, 2)) MB`n`nLog disponível em: $($script:LogPath)",
        "Sucesso",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

# Mostrar Formulário
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()

# Finalizar
Out-LogBuffer
Write-Log -Message "=== Aplicação Encerrada ===" -Level INFO

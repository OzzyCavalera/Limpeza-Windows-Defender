#REQUIRES -Version 5.1
#REQUIRES -RunAsAdministrator

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic

# ========================================
# PARAMETROS (CORRIGIDO: param() no início)
# ========================================
param(
    [switch]$SafeMode,
    [switch]$Quiet,
    [switch]$CleanAll,
    [string]$LogPath = "$env:TEMP\CleanDefender.log"
)

# ConfiguraÃ§Ã£o de execuÃ§Ã£o
$ErrorActionPreference = "Stop"
$WarningPreference = "Continue"
$ProgressPreference = "SilentlyContinue"

# VerificaÃ§Ã£o de modo de seguranÃ§a e carregamento condicional de assemblies
$isSafeMode = [bool]$SafeMode

try {
    if (-not $isSafeMode) {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
    }
} catch {
    $isSafeMode = $true
    if (-not $Quiet) {
        Write-Warning "Modo de seguranÃ§a ativado: Interfaces grÃ¡ficas nÃ£o disponÃ­veis"
    }
}

# FunÃ§Ã£o de logging aprimorada
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
    
    try {
        Add-Content -Path $LogPath -Value $logEntry -ErrorAction Stop
    } catch {
        try {
            Add-Content -Path "$env:TEMP\CleanDefender_fallback.log" -Value $logEntry -ErrorAction Stop
        } catch {}
    }
    
    if ($ShowInConsole -or $Quiet) {
        switch ($Level) {
            "ERROR" { Write-Host $Message -ForegroundColor Red }
            "WARNING" { Write-Host $Message -ForegroundColor Yellow }
            "SUCCESS" { Write-Host $Message -ForegroundColor Green }
            default { Write-Host $Message -ForegroundColor White }
        }
    }
}

# VerificaÃ§Ã£o de privilÃ©gios administrativos
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $message = "Este aplicativo requer privilÃ©gios de administrador."
    Write-Log -Message $message -Level ERROR -ShowInConsole
    
    if (-not $isSafeMode -and -not $Quiet) {
        try {
            [System.Windows.Forms.MessageBox]::Show($message, "ElevaÃ§Ã£o NecessÃ¡ria", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        } catch {}
    }
    
    if (-not $Quiet) {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" -LogPath `"$LogPath`""
        if ($SafeMode) { $arguments += " -SafeMode" }
        if ($CleanAll) { $arguments += " -CleanAll" }
        
        try {
            Start-Process powershell -ArgumentList $arguments -Verb RunAs -Wait
        } catch {
            Write-Host "Falha ao elevar privilÃ©gios: $($_.Exception.Message)" -ForegroundColor Red
        }
        exit
    } else {
        exit 1
    }
}

# Verificar integridade do Windows Defender
function Test-DefenderIntegrity {
    Write-Log -Message "Verificando integridade do Windows Defender..." -Level INFO -ShowInConsole
    
    $defenderPaths = @(
        "$env:ProgramData\Microsoft\Windows Defender",
        "${env:ProgramFiles}\Windows Defender",
        "${env:ProgramFiles(x86)}\Windows Defender"
    )

    $defenderAvailable = $false
    $missingPaths = @()
    
    foreach ($path in $defenderPaths) {
        if (Test-Path $path) {
            $defenderAvailable = $true
            Write-Log -Message "DiretÃ³rio do Defender encontrado: $path" -Level INFO
        } else {
            $missingPaths += $path
        }
    }

    if (-not $defenderAvailable) {
        $message = "Windows Defender nÃ£o encontrado no sistema. Caminhos verificados: $($missingPaths -join ', ')"
        Write-Log -Message $message -Level ERROR -ShowInConsole
        return $false
    }
    
    try {
        $defenderService = Get-Service -Name WinDefend -ErrorAction Stop
        if ($defenderService.Status -ne "Running") {
            Write-Log -Message "ServiÃ§o do Windows Defender nÃ£o estÃ¡ em execuÃ§Ã£o" -Level WARNING
        }
    } catch {
        Write-Log -Message "ServiÃ§o do Windows Defender nÃ£o encontrado: $($_.Exception.Message)" -Level WARNING
    }
    
    return $true
}

# FunÃ§Ã£o para obter proprietÃ¡rio de arquivo/pasta
function Get-FileOwner {
    param([string]$Path)
    
    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        return $acl.Owner
    } catch {
        return $null
    }
}

# FunÃ§Ã£o para definir proprietÃ¡rio de arquivo/pasta
function Set-FileOwner {
    param([string]$Path, [string]$Owner)
    
    try {
        $acl = Get-Acl -Path $Path
        $acl.SetOwner([System.Security.Principal.NTAccount]$Owner)
        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

# FunÃ§Ã£o para tomar posse de arquivo/pasta
function Grant-FileOwnership {
    param([string]$Path)
    
    try {
        $currentOwner = Get-FileOwner -Path $Path
        if ($null -eq $currentOwner) {
            return $false
        }
        
        if ($currentOwner -notlike "*Administradores*" -and $currentOwner -notlike "*Administrators*") {
            if (Set-FileOwner -Path $Path -Owner "BUILTIN\Administrators") {
                Write-Log -Message "Propriedade alterada para Administradores: $Path" -Level INFO
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
        Write-Log -Message "Falha ao tomar posse de $Path : $($_.Exception.Message)" -Level WARNING
        return $false
    }
}

# FunÃ§Ã£o de reinicio segura
function Invoke-SystemRestart {
    param(
        [string]$Mode = "Normal"
    )
    
    $maxRetries = 3
    $retryCount = 0
    
    while ($retryCount -lt $maxRetries) {
        try {
            if ($Mode -eq "SafeMode") {
                $output = & cmd /c "bcdedit /set safeboot minimal 2>&1"
                Write-Log -Message "Comando bcdedit SafeMode saiu com: $output" -Level INFO
            } elseif ($Mode -eq "Normal") {
                $output = & cmd /c "bcdedit /deletevalue safeboot 2>&1"
                Write-Log -Message "Comando bcdedit Normal saiu com: $output" -Level INFO
            }
            
            Start-Sleep -Seconds 1
            
            $restartResult = & shutdown /r /t 5 /c "Reiniciando..." 2>&1
            Write-Log -Message "Comando shutdown saiu com: $restartResult" -Level INFO
            
            Start-Sleep -Seconds 6
            exit 0
        } catch {
            $retryCount++
            Write-Log -Message "Tentativa $retryCount falhou: $($_.Exception.Message)" -Level WARNING
            
            if ($retryCount -ge $maxRetries) {
                Write-Log -Message "Falha apÃ³s $maxRetries tentativas" -Level ERROR
                throw $_
            }
            
            Start-Sleep -Seconds 2
        }
    }
}

# FunÃ§Ã£o de limpeza aprimorada
function Invoke-DefenderCleanup {
    param(
        [bool]$CleanQuarantine = $true,
        [bool]$CleanBackups = $true,
        [bool]$CleanHistory = $true,
        [bool]$CleanLogs = $true,
        [bool]$CleanTemp = $true,
        [System.Windows.Forms.ProgressBar]$ProgressBar = $null,
        [System.Windows.Forms.RichTextBox]$ResultsBox = $null,
        [System.Windows.Forms.Label]$StatusLabel = $null
    )
    
    $spaceFreed = 0
    $operations = @()
    
    if ($CleanQuarantine) { $operations += "Quarentena" }
    if ($CleanBackups) { $operations += "Backups" }
    if ($CleanHistory) { $operations += "Historico" }
    if ($CleanLogs) { $operations += "Logs" }
    if ($CleanTemp) { $operations += "Temporarios" }
    
    $totalSteps = $operations.Count
    $currentStep = 0
    
    if ($StatusLabel -and $ProgressBar) {
        $StatusLabel.Text = "Iniciando limpeza..."
        $ProgressBar.Value = 0
    }
    
    if ($ResultsBox) {
        $ResultsBox.Text = "Iniciando limpeza do Windows Defender...`n"
    }
    
    Write-Log -Message "Iniciando limpeza do Windows Defender" -Level INFO -ShowInConsole
    
    foreach ($operation in $operations) {
        $currentStep++
        
        if ($ProgressBar) {
            $ProgressBar.Value = [math]::Min(($currentStep / $totalSteps) * 100, 100)
        }
        
        $message = "Executando operacao: $operation"
        if ($ResultsBox) {
            $ResultsBox.AppendText("$message...`n")
        }
        Write-Log -Message $message -Level INFO -ShowInConsole
        
        switch ($operation) {
            "Quarentena" {
                try {
                    $quarantinePath = "$env:ProgramData\Microsoft\Windows Defender\Quarantine"
                    if (Test-Path $quarantinePath) {
                        Grant-FileOwnership -Path $quarantinePath
                        
                        $size = (Get-ChildItem -Path $quarantinePath -Recurse -Force -ErrorAction SilentlyContinue | 
                                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                        
                        Get-ChildItem -Path $quarantinePath -Recurse -Force -ErrorAction SilentlyContinue | 
                            ForEach-Object {
                                try {
                                    Grant-FileOwnership -Path $_.FullName
                                    Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                                } catch {
                                    Write-Log -Message "Falha ao excluir $($_.FullName): $($_.Exception.Message)" -Level WARNING
                                }
                            }
                        
                        $spaceFreed += if ($size) { $size } else { 0 }
                        $successMsg = "Quarentena limpa (Liberados: {0:N2} MB)" -f (($size / 1MB))
                        
                        if ($ResultsBox) {
                            $ResultsBox.AppendText("Quarentena limpa - $successMsg`n")
                        }
                        Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole
                    } else {
                        $notFoundMsg = "Pasta de quarentena nao encontrada"
                        if ($ResultsBox) {
                            $ResultsBox.AppendText("$notFoundMsg`n")
                        }
                        Write-Log -Message $notFoundMsg -Level INFO
                    }
                } catch { 
                    $errorMsg = "Erro na quarentena: $($_.Exception.Message)"
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("ERRO: $errorMsg`n")
                    }
                    Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
                }
            }
            
            "Backups" {
                try {
                    $backupPaths = @(
                        "$env:ProgramData\Microsoft\Windows Defender\Backup",
                        "$env:ProgramData\Microsoft\Windows Defender\Definition Updates\Backup",
                        "$env:ProgramData\Microsoft\Windows Defender\Platform\*\Backup",
                        "${env:ProgramFiles}\Windows Defender\Backup",
                        "${env:ProgramFiles(x86)}\Windows Defender\Backup"
                    )
                    
                    $totalBackupSize = 0
                    foreach ($path in $backupPaths) {
                        if (Test-Path $path) {
                            Grant-FileOwnership -Path $path
                            
                            $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                            
                            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                ForEach-Object {
                                    try {
                                        Grant-FileOwnership -Path $_.FullName
                                        Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                                    } catch {
                                        Write-Log -Message "Falha ao excluir $($_.FullName): $($_.Exception.Message)" -Level WARNING
                                    }
                                }
                            
                            $totalBackupSize += if ($size) { $size } else { 0 }
                        }
                    }
                    
                    $spaceFreed += $totalBackupSize
                    $successMsg = "Backups removidos (Liberados: {0:N2} MB)" -f (($totalBackupSize / 1MB))
                    
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("Backups limpos - $successMsg`n")
                    }
                    Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole
                } catch { 
                    $errorMsg = "Erro nos backups: $($_.Exception.Message)"
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("ERRO: $errorMsg`n")
                    }
                    Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
                }
            }
            
            "Historico" {
                try {
                    $historyPath = "$env:ProgramData\Microsoft\Windows Defender\Scans\History"
                    
                    if (Test-Path $historyPath) {
                        Grant-FileOwnership -Path $historyPath
                        
                        $size = (Get-ChildItem -Path $historyPath -Recurse -Force -ErrorAction SilentlyContinue | 
                                Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                        
                        try {
                            Set-MpPreference -ScanPurgeItems -ErrorAction Stop
                            $successMsg = "Historico limpo via Set-MpPreference"
                            Write-Log -Message $successMsg -Level SUCCESS
                        } catch {
                            Write-Log -Message "Falha no Set-MpPreference, usando metodo manual: $($_.Exception.Message)" -Level WARNING
                            
                            Get-ChildItem -Path $historyPath -Recurse -Force -ErrorAction SilentlyContinue | 
                                ForEach-Object {
                                    try {
                                        Grant-FileOwnership -Path $_.FullName
                                        Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                                    } catch {
                                        Write-Log -Message "Falha ao remover $($_.FullName): $($_.Exception.Message)" -Level WARNING
                                    }
                                }
                            
                            $successMsg = "Historico limpo manualmente"
                        }
                        
                        $spaceFreed += if ($size) { $size } else { 0 }
                        $successMsg += " (Liberados: {0:N2} MB)" -f (($size / 1MB))
                        
                        if ($ResultsBox) {
                            $ResultsBox.AppendText("Historico limpo - $successMsg`n")
                        }
                        Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole
                    } else {
                        $notFoundMsg = "Pasta de historico nao encontrada"
                        if ($ResultsBox) {
                            $ResultsBox.AppendText("$notFoundMsg`n")
                        }
                        Write-Log -Message $notFoundMsg -Level INFO
                    }
                } catch { 
                    $errorMsg = "Erro no historico: $($_.Exception.Message)"
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("ERRO: $errorMsg`n")
                    }
                    Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
                }
            }
            
            "Logs" {
                try {
                    try {
                        wevtutil clear-log "Microsoft-Windows-Windows Defender/Operational"
                        $successMsg = "Logs de evento limpos"
                        Write-Log -Message $successMsg -Level SUCCESS
                    } catch {
                        Write-Log -Message "Falha ao limpar logs de evento: $($_.Exception.Message)" -Level WARNING
                    }
                    
                    $logPaths = @(
                        "$env:ProgramData\Microsoft\Windows Defender\Support\*.log",
                        "$env:ProgramData\Microsoft\Windows Defender\Scans\*.log",
                        "$env:ProgramData\Microsoft\Windows Defender\*.log"
                    )
                    
                    $totalLogSize = 0
                    foreach ($path in $logPaths) {
                        if (Test-Path $path) {
                            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                ForEach-Object {
                                    try {
                                        Grant-FileOwnership -Path $_.FullName
                                    } catch {
                                        Write-Log -Message "Falha ao tomar posse de $($_.FullName): $($_.Exception.Message)" -Level WARNING
                                    }
                                }
                            
                            $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                            
                            Remove-Item -Path $path -Force -ErrorAction Stop
                            $totalLogSize += if ($size) { $size } else { 0 }
                        }
                    }
                    
                    $spaceFreed += $totalLogSize
                    $successMsg = "Logs removidos (Liberados: {0:N2} MB)" -f (($totalLogSize / 1MB))
                    
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("Logs limpos - $successMsg`n")
                    }
                    Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole
                } catch {
                    $errorMsg = "Erro nos logs: $($_.Exception.Message)"
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("ERRO: $errorMsg`n")
                    }
                    Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
                }
            }
            
            "Temporarios" {
                try {
                    $tempPaths = @(
                        "$env:ProgramData\Microsoft\Windows Defender\Scans\Temp",
                        "$env:ProgramData\Microsoft\Windows Defender\Platform\*\Temp",
                        "${env:ProgramFiles}\Windows Defender\Temp",
                        "${env:ProgramFiles(x86)}\Windows Defender\Temp",
                        "$env:TEMP\Windows Defender"
                    )
                    
                    $totalTempSize = 0
                    foreach ($path in $tempPaths) {
                        if (Test-Path $path) {
                            Grant-FileOwnership -Path $path
                            
                            $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                    Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
                            
                            Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                                ForEach-Object {
                                    try {
                                        Grant-FileOwnership -Path $_.FullName
                                        Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                                    } catch {
                                        Write-Log -Message "Falha ao excluir $($_.FullName): $($_.Exception.Message)" -Level WARNING
                                    }
                                }
                            $totalTempSize += if ($size) { $size } else { 0 }
                        }
                    }
                    
                    $spaceFreed += $totalTempSize
                    $successMsg = "Arquivos temporarios limpos (Liberados: {0:N2} MB)" -f (($totalTempSize / 1MB))
                    
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("Temporarios limpos - $successMsg`n")
                    }
                    Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole
                } catch { 
                    $errorMsg = "Erro nos temporarios: $($_.Exception.Message)"
                    if ($ResultsBox) {
                        $ResultsBox.AppendText("ERRO: $errorMsg`n")
                    }
                    Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
                }
            }
        }
        
        if (-not $Quiet -and -not $isSafeMode) {
            [System.Windows.Forms.Application]::DoEvents()
            Start-Sleep -Milliseconds 200
        }
    }
    
    $completionMsg = "Limpeza concluida! Espaco total liberado: {0:N2} MB" -f (($spaceFreed / 1MB))
    
    if ($ResultsBox) {
        $ResultsBox.AppendText("`n$completionMsg`n")
    }
    
    if ($StatusLabel) {
        $StatusLabel.Text = $completionMsg
    }
    
    if ($ProgressBar) {
        $ProgressBar.Value = 100
    }
    
    Write-Log -Message $completionMsg -Level SUCCESS -ShowInConsole
    
    return $spaceFreed
}


# Funcao para limpar cache de assinaturas antigas (APENAS EM MODO NORMAL)
function Invoke-CleanSignatureCache {
    param(
        [System.Windows.Forms.RichTextBox]$ResultsBox = $null,
        [System.Windows.Forms.ProgressBar]$ProgressBar = $null,
        [System.Windows.Forms.Label]$StatusLabel = $null
    )

    # VERIFICAÃ‡ÃƒO CRÃTICA: Nao fazer isto em modo seguro!
    if ($isSafeMode) {
        $warningMsg = "Limpeza de Assinaturas Antigas desativada em modo seguro (pode corromper o Defender)"
        if ($ResultsBox) { $ResultsBox.AppendText("$warningMsg`n") }
        Write-Log -Message $warningMsg -Level WARNING
        return 0
    }

    try {
        $message = "Limpando cache de assinaturas antigas..."
        if ($ResultsBox) { $ResultsBox.AppendText("$message`n") }
        Write-Log -Message $message -Level INFO -ShowInConsole

        $signaturePaths = @(
            "$env:ProgramData\Microsoft\Windows Defender\Definition Updates\Backup",
            "$env:ProgramData\Microsoft\Windows Defender\Platform\*\Definition Updates\Backup"
        )

        $totalSize = 0
        foreach ($path in $signaturePaths) {
            try {
                if (Test-Path $path) {
                    Grant-FileOwnership -Path $path -ErrorAction SilentlyContinue

                    $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                            Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum

                    Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                        ForEach-Object {
                            try {
                                Grant-FileOwnership -Path $_.FullName
                                Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                            } catch {
                                Write-Log -Message "Aviso ao remover $($_.FullName): $($_.Exception.Message)" -Level WARNING
                            }
                        }

                    $totalSize += if ($size) { $size } else { 0 }
                }
            } catch {
                Write-Log -Message "Aviso ao processar $path : $($_.Exception.Message)" -Level WARNING
            }
        }

        $successMsg = "Cache de assinaturas antigas limpo (Liberados: {0:N2} MB)" -f (($totalSize / 1MB))
        if ($ResultsBox) { $ResultsBox.AppendText("$successMsg`n") }
        Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole

        return $totalSize
    } catch {
        $errorMsg = "Erro ao limpar cache de assinaturas: $($_.Exception.Message)"
        if ($ResultsBox) { $ResultsBox.AppendText("ERRO: $errorMsg`n") }
        Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
        return 0
    }
}

# Funcao para limpar exclusoes do utilizador (APENAS EM MODO NORMAL)
function Invoke-CleanUserExclusions {
    param(
        [System.Windows.Forms.RichTextBox]$ResultsBox = $null,
        [System.Windows.Forms.ProgressBar]$ProgressBar = $null,
        [System.Windows.Forms.Label]$StatusLabel = $null
    )

    # VERIFICAÃ‡ÃƒO CRÃTICA: Nao fazer isto em modo seguro!
    if ($isSafeMode) {
        $warningMsg = "Limpeza de Exclusoes desativada em modo seguro (Remove-MpPreference pode falhar)"
        if ($ResultsBox) { $ResultsBox.AppendText("$warningMsg`n") }
        Write-Log -Message $warningMsg -Level WARNING
        return 0
    }

    try {
        # Mostrar confirmacao
        $confirmResult = [System.Windows.Forms.MessageBox]::Show(
            "Tem a certeza que deseja remover TODAS as exclusoes do Windows Defender?`n`n" +
            "Isto vai remover:`n" +
            "- Ficheiros e pastas excluidas`n" +
            "- Processos excluidos`n" +
            "- Extensoes de ficheiros excluidas`n" +
            "- IPs da rede excluidos`n`n" +
            "Esta acao nao pode ser desfeita. Tem a certeza?",
            "Confirmacao - Remover Exclusoes",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button2
        )

        if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) {
            $message = "Limpeza de exclusoes cancelada pelo utilizador"
            if ($ResultsBox) { $ResultsBox.AppendText("$message`n") }
            Write-Log -Message $message -Level INFO
            return 0
        }

        $message = "Removendo exclusoes do utilizador..."
        if ($ResultsBox) { $ResultsBox.AppendText("$message`n") }
        Write-Log -Message $message -Level INFO -ShowInConsole

        try {
            # Remover exclusoes de caminhos
            $paths = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath -ErrorAction SilentlyContinue
            if ($paths) {
                Remove-MpPreference -ExclusionPath $paths -ErrorAction SilentlyContinue
                Write-Log -Message "Exclusoes de caminho removidas" -Level INFO
            }
        } catch {
            Write-Log -Message "Aviso ao remover exclusoes de caminho: $($_.Exception.Message)" -Level WARNING
        }

        try {
            # Remover exclusoes de extensoes
            $extensions = Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension -ErrorAction SilentlyContinue
            if ($extensions) {
                Remove-MpPreference -ExclusionExtension $extensions -ErrorAction SilentlyContinue
                Write-Log -Message "Exclusoes de extensao removidas" -Level INFO
            }
        } catch {
            Write-Log -Message "Aviso ao remover exclusoes de extensao: $($_.Exception.Message)" -Level WARNING
        }

        try {
            # Remover exclusoes de processos
            $processes = Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess -ErrorAction SilentlyContinue
            if ($processes) {
                Remove-MpPreference -ExclusionProcess $processes -ErrorAction SilentlyContinue
                Write-Log -Message "Exclusoes de processo removidas" -Level INFO
            }
        } catch {
            Write-Log -Message "Aviso ao remover exclusoes de processo: $($_.Exception.Message)" -Level WARNING
        }

        try {
            # Remover exclusoes de IPs
            $ips = Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress -ErrorAction SilentlyContinue
            if ($ips) {
                Remove-MpPreference -ExclusionIpAddress $ips -ErrorAction SilentlyContinue
                Write-Log -Message "Exclusoes de IP removidas" -Level INFO
            }
        } catch {
            Write-Log -Message "Aviso ao remover exclusoes de IP: $($_.Exception.Message)" -Level WARNING
        }

        $successMsg = "Todas as exclusoes do utilizador foram removidas com sucesso"
        if ($ResultsBox) { $ResultsBox.AppendText("$successMsg`n") }
        Write-Log -Message $successMsg -Level SUCCESS -ShowInConsole

        return 1
    } catch {
        $errorMsg = "Erro ao remover exclusoes: $($_.Exception.Message)"
        if ($ResultsBox) { $ResultsBox.AppendText("ERRO: $errorMsg`n") }
        Write-Log -Message $errorMsg -Level ERROR -ShowInConsole
        return 0
    }
}


# Interface de linha de comando para modo quiet/safe
if ($Quiet -or $isSafeMode) {
    Write-Log -Message "Executando em modo quieto/seguro" -Level INFO -ShowInConsole
    
    if (-not (Test-DefenderIntegrity)) {
        exit 1
    }
    
    if ($CleanAll) {
        $spaceFreed = Invoke-DefenderCleanup -CleanQuarantine $true -CleanBackups $true -CleanHistory $true -CleanLogs $true -CleanTemp $true
        Write-Log -Message ("Limpeza completa concluida. Espaco liberado: {0:N2} MB" -f ($spaceFreed / 1MB)) -Level SUCCESS -ShowInConsole
    } else {
        Write-Host "Selecione as opcoes de limpeza:" -ForegroundColor White
        Write-Host "1 - Limpar Quarentena" -ForegroundColor Gray
        Write-Host "2 - Limpar Backups" -ForegroundColor Gray
        Write-Host "3 - Limpar Historico" -ForegroundColor Gray
        Write-Host "4 - Limpar Logs" -ForegroundColor Gray
        Write-Host "5 - Limpar Arquivos Temporarios" -ForegroundColor Gray
        Write-Host "6 - Limpar Tudo" -ForegroundColor Green
        Write-Host "0 - Sair" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host "Digite sua escolha (0-6)"
        
        switch ($choice) {
            '1' { $spaceFreed = Invoke-DefenderCleanup -CleanQuarantine $true }
            '2' { $spaceFreed = Invoke-DefenderCleanup -CleanBackups $true }
            '3' { $spaceFreed = Invoke-DefenderCleanup -CleanHistory $true }
            '4' { $spaceFreed = Invoke-DefenderCleanup -CleanLogs $true }
            '5' { $spaceFreed = Invoke-DefenderCleanup -CleanTemp $true }
            '6' { $spaceFreed = Invoke-DefenderCleanup -CleanQuarantine $true -CleanBackups $true -CleanHistory $true -CleanLogs $true -CleanTemp $true }
            '0' { exit }
            default {
                Write-Log -Message "Opcao invalida." -Level ERROR -ShowInConsole
                exit 1
            }
        }
        
        Write-Host "Limpeza concluida! Espaco liberado: $([math]::Round($spaceFreed/1MB, 2)) MB" -ForegroundColor Green
    }
    
    if (-not $Quiet) {
        pause
    }
    exit
}

# Interface grÃ¡fica para modo normal
$form = New-Object System.Windows.Forms.Form
$form.Text = "Otimizador do Windows Defender"
$form.Size = New-Object System.Drawing.Size(600, 760)
$form.StartPosition = "CenterScreen"
$form.BackColor = "#2e2e2e"
$form.ForeColor = "White"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# ========================================
# HEADER: SÓ GRADIENTE + TEXTO PRETO (SEM FUNDO ESCURO)
# ========================================

$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Height = 80
$headerPanel.Dock = 'Top'
$headerPanel.BackColor = [System.Drawing.Color]::Transparent  # Fundo transparente
$form.Controls.Add($headerPanel)

# Gradiente simulado (sem Drawing2D)
$headerPanel.Add_Paint({
    $rect = $headerPanel.ClientRectangle
    $g = $_.Graphics

    # Cores do gradiente
    $color1 = [System.Drawing.Color]::FromArgb(0, 122, 255)   # Azul Portugal
    $color2 = [System.Drawing.Color]::FromArgb(255, 198, 30) # Dourado Premium

    $steps = 60
    for ($i = 0; $i -lt $steps; $i++) {
        $ratio = $i / ($steps - 1)
        $r = [int]($color1.R + ($color2.R - $color1.R) * $ratio)
        $g_ = [int]($color1.G + ($color2.G - $color1.G) * $ratio)
        $b = [int]($color1.B + ($color2.B - $color1.B) * $ratio)
        $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb($r, $g_, $b))
        $x = [int]($rect.Width * $ratio)
        $width = [int]($rect.Width / $steps) + 1
        $g.FillRectangle($brush, $x, 0, $width, $rect.Height)
        $brush.Dispose()
    }
})

# Título principal (PRETO)
$labelTitle = New-Object System.Windows.Forms.Label
$labelTitle.Text = "Limpeza Avançada do Windows Defender"
$labelTitle.Font = New-Object System.Drawing.Font("Segoe UI Light", 20, [System.Drawing.FontStyle]::Bold)
$labelTitle.ForeColor = [System.Drawing.Color]::Black  # PRETO
$labelTitle.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$labelTitle.AutoSize = $false
$labelTitle.Size = New-Object System.Drawing.Size(560, 40)
$labelTitle.Location = New-Object System.Drawing.Point(10, 15)
$headerPanel.Controls.Add($labelTitle)

# Subtítulo (PRETO)
$labelSubtitle = New-Object System.Windows.Forms.Label
$labelSubtitle.Text = "Otimização completa • Seguro • Eficaz"
$labelSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$labelSubtitle.ForeColor = [System.Drawing.Color]::Black  # PRETO
$labelSubtitle.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$labelSubtitle.AutoSize = $false
$labelSubtitle.Size = New-Object System.Drawing.Size(560, 20)
$labelSubtitle.Location = New-Object System.Drawing.Point(10, 55)
$headerPanel.Controls.Add($labelSubtitle)

# Tooltip global
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.BackColor = [System.Drawing.Color]::LightYellow
$toolTip.ForeColor = [System.Drawing.Color]::Black
$toolTip.AutoPopDelay = 10000
$toolTip.InitialDelay = 500
$toolTip.ReshowDelay = 250

# Checkboxes para seleÃ§Ã£o de limpeza
$checkBoxes = @()
$items = @(
    @{Name = "Quarentena"; Description = "Remove arquivos em quarentena do Windows Defender"},
    @{Name = "Backups"; Description = "Exclui copias de seguranca de definicoes de virus"},
    @{Name = "Historico"; Description = "Limpa historico de verificacoes e acoes"},
    @{Name = "Logs"; Description = "Remove arquivos de log antigos do Defender"},
    @{Name = "Temporarios"; Description = "Limpa cache e arquivos temporarios do Defender"},
    @{Name = "Assinaturas Antigas"; Description = "Remove cache de assinaturas de virus antigas (APENAS MODO NORMAL)"},
    @{Name = "Exclusões do Utilizador"; Description = "Remove TODAS as exclusões - AVISO: Irreversivel (APENAS MODO NORMAL)"}
)

$yPos = 80
foreach ($item in $items) {
    $cb = New-Object System.Windows.Forms.CheckBox
    $cb.Text = $item.Name
    $cb.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $cb.Size = New-Object System.Drawing.Size(250, 30)
    $cb.Location = New-Object System.Drawing.Point(50, $yPos)
    $cb.Checked = $true
    $cb.Checked = ($item.Name -ne "Assinaturas Antigas") -and ($item.Name -ne "Exclusões do Utilizador")
    $toolTip.SetToolTip($cb, $item.Description)
    $form.Controls.Add($cb)
    $checkBoxes += $cb
    $yPos += 32
}

# BotÃ£o de seleÃ§Ã£o rÃ¡pida
$selectAllButton = New-Object System.Windows.Forms.Button
$selectAllButton.Text = "Selecionar Tudo"
$selectAllButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$selectAllButton.Size = New-Object System.Drawing.Size(120, 30)
$selectAllButton.Location = New-Object System.Drawing.Point(350, 119)
$selectAllButton.BackColor = "#5cb85c"
$selectAllButton.ForeColor = "Black"
$selectAllButton.Add_Click({
    foreach ($cb in $checkBoxes) {
        $cb.Checked = $true
    }
})
$form.Controls.Add($selectAllButton)

$deselectAllButton = New-Object System.Windows.Forms.Button
$deselectAllButton.Text = "Desmarcar Tudo"
$deselectAllButton.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$deselectAllButton.Size = New-Object System.Drawing.Size(120, 30)
$deselectAllButton.Location = New-Object System.Drawing.Point(350, 155)
$deselectAllButton.BackColor = "#f0ad4e"
$deselectAllButton.ForeColor = "Black"
$deselectAllButton.Add_Click({
    foreach ($cb in $checkBoxes) {
        $cb.Checked = $false
    }
})
$form.Controls.Add($deselectAllButton)

# BotÃ£o de limpeza
$btnClean = New-Object System.Windows.Forms.Button
$btnClean.Text = "Executar Limpeza"
$btnClean.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
$btnClean.Size = New-Object System.Drawing.Size(200, 50)
$btnClean.Location = New-Object System.Drawing.Point(305, 220)
$btnClean.BackColor = "#0078d7"
$btnClean.ForeColor = "White"
$toolTip.SetToolTip($btnClean, "Executa a limpeza nos itens selecionados")
$form.Controls.Add($btnClean)

# Barra de progresso
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Size = New-Object System.Drawing.Size(550, 30)
$progressBar.Location = New-Object System.Drawing.Point(20, 310)
$progressBar.Style = "Continuous"
$form.Controls.Add($progressBar)

# Ãrea de resultados
$textBoxResults = New-Object System.Windows.Forms.RichTextBox
$textBoxResults.Size = New-Object System.Drawing.Size(550, 200)
$textBoxResults.Location = New-Object System.Drawing.Point(20, 350)
$textBoxResults.BackColor = "#1e1e1e"
$textBoxResults.ForeColor = "White"
$textBoxResults.ReadOnly = $true
$form.Controls.Add($textBoxResults)

# Texto informativo sobre modo seguro
$infoSafeModeLabel = New-Object System.Windows.Forms.Label
$infoSafeModeLabel.Text = "Para limpeza completa executar em Modo Seguro e Normal.`n      No Modo Seguro as últimas opções ficam protegidas:"
$infoSafeModeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Italic)
$infoSafeModeLabel.Size = New-Object System.Drawing.Size(450, 42)
$infoSafeModeLabel.Location = New-Object System.Drawing.Point(70, 555)
$infoSafeModeLabel.ForeColor = "#999999"
$form.Controls.Add($infoSafeModeLabel)

# BotÃ£o para reiniciar em modo seguro mÃ­nimo
$btnSafeMode = New-Object System.Windows.Forms.Button
$btnSafeMode.Text = "Modo Seguro"
$btnSafeMode.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnSafeMode.Size = New-Object System.Drawing.Size(120, 35)
$btnSafeMode.Location = New-Object System.Drawing.Point(130, 615)
$btnSafeMode.BackColor = "#f0ad4e"
$btnSafeMode.ForeColor = "Black"
$toolTip.SetToolTip($btnSafeMode, "Reinicia o PC em modo seguro minimo para limpeza mais completa")
$btnSafeMode.Add_Click({
    $confirmResult = [System.Windows.Forms.MessageBox]::Show("O PC sera reiniciado em modo seguro minimo. Execute este aplicativo apos o reinicio.", "Confirmacao", [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Information)
    if ($confirmResult -eq [System.Windows.Forms.DialogResult]::OK) {
        Write-Log -Message "Reiniciando em modo seguro minimo..." -Level INFO -ShowInConsole
        Invoke-SystemRestart -Mode "SafeMode"
    }
})
$form.Controls.Add($btnSafeMode)

# BotÃ£o para reiniciar em modo normal
$btnNormalMode = New-Object System.Windows.Forms.Button
$btnNormalMode.Text = "Modo Normal"
$btnNormalMode.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnNormalMode.Size = New-Object System.Drawing.Size(120, 35)
$btnNormalMode.Location = New-Object System.Drawing.Point(340, 615)
$btnNormalMode.BackColor = "#5cb85c"
$btnNormalMode.ForeColor = "Black"
$toolTip.SetToolTip($btnNormalMode, "Reinicia o PC em modo normal apos limpeza em modo seguro")
$btnNormalMode.Add_Click({
    $confirmResult = [System.Windows.Forms.MessageBox]::Show("O PC sera reiniciado em modo normal.", "Confirmacao", [System.Windows.Forms.MessageBoxButtons]::OKCancel, [System.Windows.Forms.MessageBoxIcon]::Information)
    if ($confirmResult -eq [System.Windows.Forms.DialogResult]::OK) {
        Write-Log -Message "Reiniciando em modo normal..." -Level INFO -ShowInConsole
        Invoke-SystemRestart -Mode "Normal"
    }
})
$form.Controls.Add($btnNormalMode)

# Status do sistema
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Pronto"
$statusLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$statusLabel.Size = New-Object System.Drawing.Size(550, 20)
$statusLabel.Location = New-Object System.Drawing.Point(20, 665)
$statusLabel.TextAlign = "MiddleLeft"
$form.Controls.Add($statusLabel)

# Evento do botÃ£o de limpeza
$btnClean.Add_Click({
    $selectedItems = $checkBoxes | Where-Object { $_.Checked }
    if ($selectedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Selecione pelo menos uma opcao para limpar.", "Nenhuma Selecao", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    
    Invoke-DefenderCleanup -CleanQuarantine ($selectedItems.Text -contains "Quarentena") `
                          -CleanBackups ($selectedItems.Text -contains "Backups") `
                          -CleanHistory ($selectedItems.Text -contains "Historico") `
                          -CleanLogs ($selectedItems.Text -contains "Logs") `
                          -CleanTemp ($selectedItems.Text -contains "Temporarios") `
                          -ProgressBar $progressBar `
                          -ResultsBox $textBoxResults `
                          -StatusLabel $statusLabel
})

# Tooltip de informaÃ§Ãµes
$infoLabel = New-Object System.Windows.Forms.Label
$infoLabel.Text = "i"
$infoLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14)
$infoLabel.Size = New-Object System.Drawing.Size(30, 30)
$infoLabel.Location = New-Object System.Drawing.Point(530, 25)
$infoLabel.Cursor = [System.Windows.Forms.Cursors]::Hand
$toolTip.SetToolTip($infoLabel, "Selecione os itens para limpar e clique em Executar.`nRequer execucao como administrador.`nCompativel com Windows 10/11/LTSC.")
$form.Controls.Add($infoLabel)

# InformaÃ§Ãµes de versÃ£o
$versionLabel = New-Object System.Windows.Forms.Label
$versionLabel.Text = "v6.6.6 - Ozzy Cavalera"
$versionLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$versionLabel.Size = New-Object System.Drawing.Size(150, 22)
$versionLabel.Location = New-Object System.Drawing.Point(20, 685)
$versionLabel.ForeColor = "LightGray"
$form.Controls.Add($versionLabel)

# BotÃ£o de visualizaÃ§Ã£o de log
$viewLogButton = New-Object System.Windows.Forms.Button
$viewLogButton.Text = "Ver Log"
$viewLogButton.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$viewLogButton.Size = New-Object System.Drawing.Size(80, 30)
$viewLogButton.Location = New-Object System.Drawing.Point(480, 685)
$viewLogButton.BackColor = "#555555"
$viewLogButton.ForeColor = "White"
$viewLogButton.Add_Click({
    try {
        if (Test-Path $script:LogPath) {
            Invoke-Item $script:LogPath
        } else {
            [System.Windows.Forms.MessageBox]::Show("Arquivo de log nao encontrado.", "Informacao", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Nao foi possivel abrir o arquivo de log: $($_.Exception.Message)", "Erro", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
# VerificaÃ§Ã£o de integridade ao iniciar
if (-not (Test-DefenderIntegrity)) {
    $message = "Windows Defender nao foi detectado neste sistema. A limpeza pode nao ser eficaz."
    [System.Windows.Forms.MessageBox]::Show($message, "Aviso do Sistema", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    Write-Log -Message $message -Level WARNING -ShowInConsole
}

[void]$form.ShowDialog()

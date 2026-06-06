# ==============================================================================
# MECZ FORENSIC MOD ANALYZER (FIXED CRASH)
# ==============================================================================

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName System.Windows.Forms

# --- GUI DEFINITION ---
[xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Mecz Forensic Tool"
    Width="900"
    Height="600"
    WindowStartupLocation="CenterScreen"
    ResizeMode="CanMinimize"
    Background="#1e1e1e"
    Foreground="White"
    FontFamily="Segoe UI">

    <Grid Margin="15">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <!-- Header -->
        <TextBlock Grid.Row="0" Text="MINECRAFT FORENSIC TOOL" FontSize="22" FontWeight="Bold" Foreground="#00ffcc" Margin="0,0,0,15"/>

        <!-- Controls -->
        <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,15">
            <Button x:Name="BrowseBtn" Content="Browse Folder" Width="120" Height="35" Background="#444" Foreground="White" Margin="0,0,10,0" FontSize="12"/>
            <Button x:Name="PasteBtn"   Content="PASTE PATH" Width="120" Height="35" Background="#007acc" Foreground="White" Margin="0,0,10,0" FontWeight="Bold" FontSize="12"/>
            <Button x:Name="AnalyzeBtn" Content="ANALYZE"     Width="120" Height="35" Background="#28a745" Foreground="White" FontWeight="Bold" FontSize="12"/>

            <!-- PATH BOX -->
            <TextBox x:Name="PathBox" 
                     Width="440" 
                     Height="35" 
                     Background="#333" 
                     Foreground="White" 
                     BorderBrush="#555" 
                     Text="PASTE PATH HERE OR CLICK BROWSE" 
                     VerticalContentAlignment="Center"
                     Margin="10,0,0,0"/>
        </StackPanel>

        <!-- Output Area (Switched to Listbox for stability) -->
        <Border Grid.Row="2" BorderBrush="#444" BorderThickness="1" Background="#111">
            <ListBox x:Name="OutputBox" 
                     Background="#111" 
                     Foreground="#00ffcc" 
                     FontFamily="Consolas" 
                     FontSize="11" 
                     BorderThickness="0"/>
        </Border>
    </Grid>
</Window>
"@

# --- LOGIC ---

 $reader = New-Object System.Xml.XmlNodeReader $xaml
 $window = [Windows.Markup.XamlReader]::Load($reader)

 $BrowseBtn = $window.FindName("BrowseBtn")
 $PasteBtn  = $window.FindName("PasteBtn")
 $AnalyzeBtn = $window.FindName("AnalyzeBtn")
 $OutputBox = $window.FindName("OutputBox")
 $PathBox   = $window.FindName("PathBox")

# Suspicious Keywords (Refined)
 $SuspiciousClients = @("meteor", "liquidbounce", "wurst", "impact", "rise", "future", "tenacity", "vape", "karamel", "gomz")
 $SuspiciousKeywords = @("killaura", "fly", "scaffold", "reach", "autoclicker", "fullbright", "esp", "tracer", "noslow", "inventorymove", "timer", "autotool", "stealer", "rename", "autoeat", "crystalaura", "bedaura")

# Helper to write colored lines (FIXED CRASH)
function Write-Output {
    param([string]$text, [string]$color = "White")
    
    # Create a TextBlock for each line
    $tb = New-Object System.Windows.Controls.TextBlock
    $tb.Text = $text
    $tb.Foreground = $color # This works on a new object
    
    # Add to ListBox
    $OutputBox.Items.Add($tb)
    
    # Auto-scroll to bottom
    $OutputBox.ScrollIntoView($tb)
}

function Select-Folder {
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($FolderBrowser.ShowDialog() -eq "OK") {
        $PathBox.Text = $FolderBrowser.SelectedPath
    }
}

function Paste-Clipboard {
    try {
        $ClipboardText = [System.Windows.Forms.Clipboard]::GetText()
        if (-not [string]::IsNullOrWhiteSpace($ClipboardText)) {
            $PathBox.Text = $ClipboardText
        }
    } catch {}
}

function Start-Analysis {
    $TargetPath = $PathBox.Text

    if ([string]::IsNullOrWhiteSpace($TargetPath)) {
        [System.Windows.MessageBox]::Show("Please enter, paste, or select a path first.")
        return
    }

    if (!(Test-Path $TargetPath)) {
        [System.Windows.MessageBox]::Show("The path does not exist.`n`nPath: $TargetPath")
        return
    }

    $OutputBox.Items.Clear() # Clear previous
    Write-Output "--- STARTING ANALYSIS ---" "Cyan"
    Write-Output "Target: $TargetPath" "Gray"
    Write-Output ""

    # 1. Check Mods Folder
    $ModsPath = Join-Path $TargetPath "mods"
    if (Test-Path $ModsPath) {
        Write-Output "[1] SCANNING MODS FOLDER..." "Yellow"
        $Mods = Get-ChildItem -Path $ModsPath -Filter "*.jar" -ErrorAction SilentlyContinue
        if ($Mods) {
            foreach ($Mod in $Mods) {
                $Name = $Mod.Name.ToLower()
                $IsSuspicious = $false
                $Reason = ""

                # Check for Client Names
                foreach ($client in $SuspiciousClients) {
                    if ($Name -like "*$client*") { 
                        $IsSuspicious = $true
                        $Reason = "Known Client ($client)"
                        break
                    }
                }

                # Check for Keywords (Word Boundary)
                if (-not $IsSuspicious) {
                    foreach ($kw in $SuspiciousKeywords) {
                        if ($Name -match "\b$kw\b") { 
                            $IsSuspicious = $true
                            $Reason = "Suspicious Keyword ($kw)"
                            break
                        }
                    }
                }
                
                if ($IsSuspicious) {
                    Write-Output "  [!] FLAGGED: $($Mod.Name) - $Reason" "Red"
                } else {
                    Write-Output "  [SAFE] $($Mod.Name)" "Lime"
                }
            }
        } else {
            Write-Output "  No mods found or folder empty." "Gray"
        }
    } else {
        Write-Output "[1] MODS FOLDER NOT FOUND." "Red"
    }
    Write-Output ""

    # 2. Scan Logs
    $LogsPath = Join-Path $TargetPath "logs\latest.log"
    if (Test-Path $LogsPath) {
        Write-Output "[2] SCANNING LOGS FOR KEYWORDS..." "Yellow"
        $LogContent = Get-Content $LogsPath -ErrorAction SilentlyContinue
        $Hits = 0
        
        foreach ($line in $LogContent) {
            foreach ($client in $SuspiciousClients) {
                if ($line -match $client) {
                    $ShortLine = if ($line.Length -gt 80) { $line.Substring(0, 80) + "..." } else { $line }
                    Write-Output "  [!] LOGS FOUND '$client': $ShortLine" "Red"
                    $Hits++
                }
            }
        }
        if ($Hits -eq 0) {
            Write-Output "  No suspicious logs found." "Lime"
        }
    } else {
        Write-Output "[2] LOGS NOT FOUND." "Gray"
    }
    Write-Output ""

    # 3. Check Options (Ghost client traces)
    $OptionsPath = Join-Path $TargetPath "options.txt"
    if (Test-Path $OptionsPath) {
        Write-Output "[3] CHECKING OPTIONS.TXT..." "Yellow"
        $Options = Get-Content $OptionsPath
        
        $FovLine = $Options | Where-Object { $_ -like "fov:*" }
        if ($FovLine) {
            if ($FovLine -match "fov:(.*)") {
                $FovVal = [float]$matches[1]
                if ($FovVal -gt 130) {
                    Write-Output "  [!] HIGH FOV DETECTED: $FovLine" "Red"
                }
            }
        }

        $GammaLine = $Options | Where-Object { $_ -like "gamma:*" }
        if ($GammaLine) {
            if ($GammaLine -match "gamma:(.*)") {
                $GammaVal = [float]$matches[1]
                if ($GammaVal -gt 5.0) {
                    Write-Output "  [!] HIGH GAMMA DETECTED: $GammaLine" "Red"
                }
            }
        }
    } else {
        Write-Output "[3] OPTIONS.TXT NOT FOUND." "Gray"
    }

    Write-Output ""
    Write-Output "--- ANALYSIS COMPLETE ---" "Cyan"
}

# --- EVENTS ---
 $BrowseBtn.Add_Click({ Select-Folder })
 $PasteBtn.Add_Click({ Paste-Clipboard })
 $AnalyzeBtn.Add_Click({ Start-Analysis })

 $window.ShowDialog() | Out-Null

import subprocess
import sys
import os
import ctypes

# Firma personalizada
def print_signature():
    print("=" * 40)
    print("Script creado por: TechDroid")
    print("Descripción: Script para deshabilitar permanentemente la protección en tiempo real de Windows Defender")
    print("=" * 40)
    print("")

# Verificar si el script se ejecuta con privilegios de administrador
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

# Función para ejecutar el comando PowerShell
def execute_powershell(command):
    try:
        result = subprocess.run(["powershell", "-Command", command], capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar el comando: {e}")
        return None

# Función para verificar el estado de Windows Defender
def check_defender_status():
    print("Verificando el estado de Windows Defender...")
    status_command = 'Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring'
    status = execute_powershell(status_command)
    if status == "True":
        print("La protección en tiempo real está deshabilitada.")
    elif status == "False":
        print("La protección en tiempo real está habilitada.")
    else:
        print("No se pudo determinar el estado de Windows Defender.")

# Deshabilitar la protección en tiempo real de Windows Defender de forma permanente
def disable_defender_permanently():
    print("Deshabilitando la protección en tiempo real de Windows Defender...")

    # Deshabilitar la protección en tiempo real de Windows Defender
    command = 'Set-MpPreference -DisableRealtimeMonitoring $true'
    output = execute_powershell(command)
    if output is not None:
        print("La protección en tiempo real de Windows Defender ha sido deshabilitada.")

    # Deshabilitar la reactivación automática de Defender
    print("Deshabilitando la reactivación automática de Windows Defender...")
    disable_reactivation_command = """
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableArchiveScanning $true
    Set-MpPreference -DisableCatchupFullScan $true
    Set-MpPreference -DisableOnAccessProtection $true
    """
    execute_powershell(disable_reactivation_command)

    # Deshabilitar las tareas programadas que podrían intentar activar Defender
    print("Deshabilitando las tareas programadas de Windows Defender...")
    disable_tasks_command = """
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Defender\*"
    """
    execute_powershell(disable_tasks_command)

    # Desactivar el servicio de Windows Defender de manera persistente
    print("Desactivando el servicio de Windows Defender para evitar reactivación...")
    disable_service_command = """
    Stop-Service -Name WinDefend
    Set-Service -Name WinDefend -StartupType Disabled
    """
    execute_powershell(disable_service_command)

    # Deshabilitar la protección de archivos en el registro de Windows
    print("Deshabilitando la protección de archivos en el registro...")
    disable_registry_command = """
    New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Value 1 -PropertyType DWord -Force
    """
    execute_powershell(disable_registry_command)

# Función para habilitar Windows Defender (si alguna vez se decide revertir)
def enable_defender():
    print("Habilitando la protección en tiempo real de Windows Defender...")

    # Habilitar la protección en tiempo real
    command = 'Set-MpPreference -DisableRealtimeMonitoring $false'
    output = execute_powershell(command)
    if output is not None:
        print("La protección en tiempo real de Windows Defender ha sido habilitada.")

    # Habilitar la reactivación automática de Defender
    print("Habilitando la reactivación automática de Windows Defender...")
    enable_reactivation_command = """
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableArchiveScanning $false
    Set-MpPreference -DisableCatchupFullScan $false
    Set-MpPreference -DisableOnAccessProtection $false
    """
    execute_powershell(enable_reactivation_command)

    # Habilitar las tareas programadas
    print("Habilitando las tareas programadas de Windows Defender...")
    enable_tasks_command = """
    Enable-ScheduledTask -TaskName "Microsoft\Windows\Defender\*"
    """
    execute_powershell(enable_tasks_command)

    # Restaurar el servicio de Windows Defender
    print("Restaurando el servicio de Windows Defender...")
    restore_service_command = """
    Set-Service -Name WinDefend -StartupType Manual
    Start-Service -Name WinDefend
    """
    execute_powershell(restore_service_command)

    # Eliminar la política en el registro de Windows
    print("Restaurando la política del registro de Windows Defender...")
    restore_registry_command = """
    Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'DisableAntiSpyware' -Force
    """
    execute_powershell(restore_registry_command)

# Función principal para habilitar o deshabilitar Windows Defender
def main(action="disable"):
    # Verificar si el script se ejecuta con permisos de administrador
    if not is_admin():
        print("Este script debe ejecutarse con privilegios de administrador.")
        return

    print_signature()

    # Verificar el estado de Windows Defender antes de hacer cualquier cambio
    if action == "check":
        check_defender_status()
    elif action == "disable":
        check_defender_status()  # Verificar el estado antes de deshabilitar
        disable_defender_permanently()
    elif action == "enable":
        check_defender_status()  # Verificar el estado antes de habilitar
        enable_defender()
    else:
        print("Acción no válida. Usa 'disable', 'enable' o 'check'.")

if __name__ == "__main__":
    # Verificar si se pasa un argumento de acción
    if len(sys.argv) > 1:
        action = sys.argv[1].lower()
        main(action)
    else:
        main()  # Si no se pasa un argumento, deshabilitar por defecto


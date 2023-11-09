#!/bin/bash

#!/bin/bash

# Function to perform security auditing
function security_audit {
    echo "Security Audit Report"
    echo "----------------------"

    # Number of security checks
    total_checks=4
    current_check=0

    # Function to update progress bar
    function update_progress {
        ((current_check++))
        progress=$((current_check * 100 / total_checks))
        echo -ne "Progress: [$progress%] $1\r"
    }

    # Check file permissions
    update_progress "Checking file permissions..."
    world_writable_files=$(find / -type f -perm -002 -exec ls -ld {} \; 2>/dev/null | wc -l)
    setuid_setgid_files=$(find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null | wc -l)
    file_permissions_issues=$((world_writable_files + setuid_setgid_files))

    # Check executable files
    update_progress "Checking executable files..."
    executable_files=$(find / -type f -executable | wc -l)

    # Check outdated software packages
    update_progress "Checking outdated software packages..."
    outdated_packages=$(apt list --upgradable 2>/dev/null | grep -cE 'upgradable')

    # Calculate security score
    total_issues=$((file_permissions_issues + executable_files + outdated_packages))
    security_score=$((100 - (total_issues * 100 / (total_checks * 100))))

    # Print results
    echo "File Permissions Issues: $file_permissions_issues"
    echo "Executable Files: $executable_files"
    echo "Outdated Software Packages: $outdated_packages"
    echo "Security Score: $security_score%"

    # Recommendations based on security audit results
    echo "Recommendations:"
    if [ $security_score -gt 80 ]; then
        echo "1. The system is secure. Good job!"
    else
        echo "1. Review and update file permissions."
        echo "2. Minimize the use of setuid and setgid files."
        echo "3. Regularly review and secure executable files."
        echo "4. Keep software up to date to patch security vulnerabilities."
        echo "5. Consider additional security measures based on specific findings."
    fi
}

# Function to perform system health check
function system_health_check {
    echo "System Health Check"
    echo "--------------------"

    # Check CPU usage
    cpu_usage=$(top -bn 1 | grep '%Cpu' | awk '{print $2}' | cut -d '.' -f1)
    echo "CPU Usage: ${cpu_usage}%"

    # Check memory usage
    memory_info=$(free -m | awk '/Mem:/ {print $3, $2}')
    used_memory=$(echo "$memory_info" | awk '{print $1}')
    total_memory=$(echo "$memory_info" | awk '{print $2}')
    memory_percentage=$(( (used_memory * 100) / total_memory ))
    echo "Memory Usage: ${memory_percentage}%"

    # Check disk space
    disk_space=$(df -h / | awk '/\// {print $(NF-1)}' | sed 's/%//')
    echo "Disk Space Usage: ${disk_space}%"

    # Check network status
    network_status=$(ping -c 1 google.com > /dev/null 2>&1 && echo "Online" || echo "Offline")
    echo "Network Status: ${network_status}"

    # Check for security vulnerabilities (example: outdated packages)
    security_issues=$(sudo apt list --upgradable 2>/dev/null | wc -l)
    echo "Security Vulnerabilities: ${security_issues}"

    # Suggestions based on health check results
    if [ "$cpu_usage" -gt 80 ]; then
        echo "Recommendation: High CPU usage detected. Check for resource-intensive processes."
    fi

    if [ "$memory_percentage" -gt 80 ]; then
        echo "Recommendation: High memory usage detected. Investigate memory-hungry processes."
    fi

    if [ "$disk_space" -gt 90 ]; then
        echo "Recommendation: Low disk space detected. Clear unnecessary files or expand storage."
    fi

    if [ "$network_status" == "Offline" ]; then
        echo "Recommendation: Network connection is offline. Check network cables and connection."
    fi

    if [ "$security_issues" -gt 0 ]; then
        echo "Recommendation: Security vulnerabilities detected. Update packages to the latest versions."
    else
        echo "Recommendation: System packages are up to date."
    fi
}



# Function to monitor detailed process information
function monitor_processes {
    echo "Process Monitoring"
    echo "------------------"

    # Display headers with additional columns
    printf "%-10s %-10s %-10s %-10s %-20s\n" "PID" "TTY" "CPU %" "MEM %" "CMD"

    # List running processes and extract relevant information
    ps -eo pid,tty,pcpu,pmem,comm --sort=-%cpu | awk 'NR <= 10 {printf "%-10s %-10s %-10s %-10s %-20s\n", $1, $2, $3, $4, $5}'
}

function display_network_info {
    echo "Network Analysis"
    echo "-----------------"
    echo "Active TCP Connections:"
    netstat -tuln | grep 'tcp'
    echo "Active UDP Connections:"
    netstat -tuln | grep 'udp'
    echo "Network Interfaces:"
    ip -o -4 address show | awk '{print "Interface:", $2, "IP Address:", $4, "Netmask:", $6, "Broadcast:", $8}'
}

# Function to display hardware information
function display_hardware_info {
    echo "Hardware Information"
    echo "--------------------"

    # CPU Information
    echo "CPU Information:"
    lscpu

    # Memory Information
    echo "Memory Information:"
    free -h

    # Disk Information
    echo "Disk Space Information:"
    df -h

    # Detailed Hardware Information
    echo "Detailed Hardware Information:"
    lshw -short
}


# Function to encrypt a file
function encrypt_file {
    echo "Enter the path of the file to encrypt:"
    read -r file_path

    if [ ! -f "$file_path" ]; then
        echo "Error: File '$file_path' not found."
        return 1
    fi

    echo "Enter passphrase for encryption:"
    read -s passphrase
    echo

    openssl enc -aes-256-cbc -salt -in "$file_path" -out "$file_path.enc" -pass "pass:$passphrase"

    if [ $? -eq 0 ]; then
        echo "Encryption successful. Encrypted file: $file_path.enc"
    else
        echo "Encryption failed."
    fi
}

# Function to decrypt a file
function decrypt_file {
    echo "Enter the path of the file to decrypt:"
    read -r file_path

    if [ ! -f "$file_path" ]; then
        echo "Error: File '$file_path' not found."
        return 1
    fi

    echo "Enter passphrase for decryption:"
    read -s passphrase
    echo

    openssl enc -d -aes-256-cbc -in "$file_path" -out "${file_path%.enc}" -pass "pass:$passphrase"

    if [ $? -eq 0 ]; then
        echo "Decryption successful. Decrypted file: ${file_path%.enc}"
    else
        echo "Decryption failed."
    fi
}


# Function to display system information
function display_system_info {
    echo "System Information"
    echo "------------------"
    echo "CPU Usage: $(top -bn1 | grep 'Cpu(s)' | awk '{print $2}')"
    echo "Memory Usage: $(free -m | awk '/Mem:/ {print $3 " MB used / " $2 " MB total"}')"
    echo "Disk Space: $(df -h / | awk '/\// {print $4 " available out of " $2}')"
    echo "Network Details: $(ifconfig | grep 'inet ' | awk '{print $2}')"
    echo "------------------"
}

# Function to display directory structure
function display_directory_structure {
    read -p "Enter the path to the directory you want to explore: " directory_path
    if [ -d "$directory_path" ]; then
        echo "Directory Structure of $directory_path"
        echo "-------------------------------------"
        tree "$directory_path"
        echo "-------------------------------------"
    else
        echo "Error: Directory not found."
    fi
}

# Function to kill a process
function kill_process {
    ps -a
    read -p "Enter the PID of the process you want to kill: " process_pid
    read -p "Are you sure you want to kill the process with PID $process_pid? (yes/no): " confirmation
    if [[ "$confirmation" == "yes" ]]; then
        kill -9 "$process_pid"
        echo "Process with PID $process_pid has been killed."
    else
        echo "Process was not killed."
    fi
}

# Function to delete a directory
function delete_directory {
    read -p "Enter the path to the directory you want to delete: " directory_path
    read -p "Are you sure you want to delete the directory at $directory_path? (yes/no): " confirmation
    if [[ "$confirmation" == "yes" ]]; then
        rm -r "$directory_path"
        echo "Directory at $directory_path has been deleted."
    else
        echo "Directory was not deleted."
    fi
}

# Main menu
function main_menu {
    echo "System Information Manager"
    echo "-------------------------"
    echo "1. Display System Information"
    echo "3. Display Directory Structure"
    echo "4. Kill a Process"
    echo "5. Delete a Directory/file"
    echo "6  Display Network information"
    echo "7. Display Hardware information"
    echo "8. Encrypt"
    echo "9. Decrypt"
    echo "10. Monitor Process"
    echo "11. System Check Health"
    echo "12. Check Security Audit"
    echo "13. Quit"
    read -p "Enter your choice: " choice

    case "$choice" in
        1)
            display_system_info
            ;;
        3)
            display_directory_structure
            ;;
        4)
            kill_process
            ;;
        5)
            delete_directory
            ;;
	6) 
	    display_network_info
	    ;;
	7)
	   display_hardware_info
	    ;;
        8)
	   encrypt_file
	    ;;
        9)
	   decrypt_file
	    ;;
       10)
	   monitor_process
	    ;;
       11)
	   system_health_check
	    ;;
       12)
           security_audit
	    ;;	   

       13)
            exit 0
            ;;
        *)
            echo "Invalid choice. Please try again."
            ;;
    esac

     read -p "Do you want to run another operation? (yes/no): " run_again
    if [[ "$run_again" == "yes" || "$run_again" == "Yes" || "$run_again" == "y" ]]; then
        main_menu
    else
        echo "Goodbye!"
        exit 0
    fi
}

# Start the main menu
main_menu

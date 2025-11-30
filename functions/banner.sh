#!/bin/bash
# banner.sh
# Original Author: Grimmie
# Version: 3.0.1

banner() {
    # Set colors
    local CYAN='\033[0;36m'
    local BLUE='\033[0;34m'
    local BOLD='\033[1m'
    local NO_COLOR='\033[0m'

    # Clear screen
    clear

    # Print ASCII banner with color
    echo -e "${CYAN}                   --                                        ${NO_COLOR}"
    echo -e "${BLUE}    ____ _ __  __ / /_ ____   ___   ____   __  __ ____ ___   ${NO_COLOR}"
    echo -e "${BLUE}   / __ `// / / // __// __ \ / _ \ / __ \ / / / // __ `__ \  ${NO_COLOR}"
    echo -e "${BLUE}  / /_/ // /_/ // /_ / /_/ //  __// / / // /_/ // / / / / /  ${NO_COLOR}"
    echo -e "${BLUE}  \__,_/ \__,_/ \__/ \____/ \___//_/ /_/ \__,_//_/ /_/ /_/   ${NO_COLOR}"
    echo -e "${CYAN}                                                             ${NO_COLOR}"

    # Author credits
    echo -e "${BOLD}${CYAN}Author: giveen${NO_COLOR} (You)"
    echo -e "${BOLD}${BLUE}Original Author: Grimmie${NO_COLOR}"
    echo -e "${BOLD}${CYAN}Version: 3.0.1${NO_COLOR}"

    # Final pause
    sleep 1.025
}

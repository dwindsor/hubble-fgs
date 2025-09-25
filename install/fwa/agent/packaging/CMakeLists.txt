cmake_minimum_required(VERSION 3.5)

project(daf)

set(DAF_COMP_ID "cpa")
set(DAF_COMP_NAME "Firewall Agent")

# Standard DAF packaging
include(cmake/packaging.cmake)

##################################################################################
# Add files to install here.  Default permissions: PROGRAMS - 0755, FILES - 0644 #
##################################################################################

# Service files
install(PROGRAMS ../fwa RENAME daf-cpa DESTINATION bin)
install(PROGRAMS install/finish DESTINATION bin)
install(PROGRAMS install/run DESTINATION bin)
install(PROGRAMS install/log DESTINATION bin)
configure_file(install/servicedir.sh.in ${CMAKE_CURRENT_BINARY_DIR}/servicedir.sh @ONLY)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/servicedir.sh DESTINATION bin)

# Utilities
# install(PROGRAMS ../fwactl RENAME fwactl DESTINATION bin)

# Always include Cpack at the end
include(CPack)

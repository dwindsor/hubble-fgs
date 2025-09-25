
set(DAF_PROD_NAME "Cisco Hypershield")
set(DAF_HOME /opt/cisco/daf)
set(DAF_BIN ${DAF_HOME}/bin)
set(DAF_ETC ${DAF_HOME}/etc)
set(DAF_LOG ${DAF_HOME}/log)

set(CMAKE_VERBOSE_MAKEFILE true)
set(CPACK_PROJECT_NAME "daf-${DAF_COMP_ID}")
set(CPACK_VERBATIM_VARIABLES true)
set(CPACK_PACKAGE_CONTACT "daf@cisco.com")


set(CPACK_PACKAGE_DESCRIPTION "${DAF_PROD_NAME} - ${DAF_COMP_NAME}")
set(CPACK_PACKAGE_VENDOR "Cisco Systems, Inc.")
set(CPACK_PACKAGE_CHECKSUM SHA256)
set(CPACK_PACKAGE_DIRECTORY "build")
set(CPACK_STRIP_FILES OFF)
set(CPACK_GENERATOR "DEB;TGZ")

# Allow commit hash to be passed in via GIT_COMMIT env var (for docker)
if (DEFINED ENV{GIT_COMMIT})
    set(commit_hash $ENV{GIT_COMMIT})
else()
    # Get commit_hash from git
    execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE commit_hash
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

if (DEFINED ENV{BUILD_NUMBER})
    # Add the Jenkins build number for automated builds
    set(CPACK_PACKAGE_VERSION 1.1.0+$ENV{BUILD_NUMBER}-${commit_hash})
else()
    # Add and ISO formatted timestamp for dev builds
    execute_process(
        COMMAND date "+%Y%m%d%H%M%S"
	OUTPUT_VARIABLE timestamp
	OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(CPACK_PACKAGE_VERSION 1.1.0+${timestamp}-${commit_hash})
endif()

if (DAF_COMP_ID STREQUAL "daf" )
    set(CPACK_PACKAGE_NAME "daf")
    set(CPACK_PACKAGING_INSTALL_PREFIX ${DAF_HOME})
else()
    set(CPACK_PACKAGE_NAME "daf-${DAF_COMP_ID}")
    set(CPACK_PACKAGING_INSTALL_PREFIX ${DAF_BIN}/${DAF_COMP_ID}/${CPACK_PACKAGE_VERSION})
endif()

# Build the package file name
execute_process(
      COMMAND bash "-c" "case $(uname -m) in
                            x86_64)  echo amd64 ;;
                            aarch64) echo arm64 ;;
                         esac"
      OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
      OUTPUT_STRIP_TRAILING_WHITESPACE
)
execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE CPACK_RPM_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if (PACKAGE_PLATFORM STREQUAL "generic")
    set(PLATFORM_PREFIX "")
elseif (PACKAGE_PLATFORM STREQUAL "elba")
    set(PLATFORM_PREFIX "${PACKAGE_PLATFORM}-")
else()
    message(FATAL_ERROR "Invalid platform, PLATFORM=${PACKAGE_PLATFORM}")
endif()

set(CPACK_PACKAGE_FILE_NAME ${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${PLATFORM_PREFIX}${CPACK_DEBIAN_PACKAGE_ARCHITECTURE})


macro(configure_rpath)
    cmake_parse_arguments(ARG
        ""
	"FILE;RPATH"
        ""
        ${ARGN}
    )
    # Update the rpath 
    message("-- Setting the RUNPATH of ${ARG_FILE} to ${ARG_RPATH}")
    execute_process(
        COMMAND patchelf --set-rpath ${ARG_RPATH} ${ARG_FILE}
        RESULT_VARIABLE ret
    )
    if(ret EQUAL "1")
	    message(FATAL_ERROR "Failed to patch the RUNPATH in $(ARG_FILE}")
    endif()
endmacro()

# Add default DEBIAN control stubs
execute_process(
    COMMAND dirname ${CMAKE_CURRENT_LIST_FILE}
    OUTPUT_VARIABLE TEMPLATE_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Add standard configuration hooks
if(${DAF_DAEMON})
    configure_file(install/etc/systemd/system/daf-${DAF_COMP_ID}.service.in ${CMAKE_CURRENT_BINARY_DIR}/daf-${DAF_COMP_ID}.service @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/daf-${DAF_COMP_ID}.service DESTINATION etc/systemd/system)
endif()

# Daf is the root package that installs to the daf home directory
if (DAF_COMP_ID STREQUAL "daf")
    set(DAF_PKG_ROOT ${DAF_HOME}/bin/daf/${CPACK_PACKAGE_VERSION})
    # Install a dummy service as a control point for system bring up
    configure_file(install/etc/systemd/system/daf.service.in ${CMAKE_CURRENT_BINARY_DIR}/daf.service @ONLY)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/daf.service DESTINATION bin/daf/${CPACK_PACKAGE_VERSION}/etc/systemd/system)
    # Install the configure hooks
    configure_file(install/bin/configure_daf.sh.in ${CMAKE_CURRENT_BINARY_DIR}/bin/configure_daf.sh @ONLY)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/bin/configure_daf.sh DESTINATION bin/daf/${CPACK_PACKAGE_VERSION}/bin)
    configure_file(install/bin/cleanup_daf.sh.in ${CMAKE_CURRENT_BINARY_DIR}/cleanup_daf.sh @ONLY)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cleanup_daf.sh DESTINATION bin/daf/${CPACK_PACKAGE_VERSION}/bin)
else()
    set(DAF_PKG_ROOT ${CPACK_PACKAGING_INSTALL_PREFIX})
    configure_file(install/configure_${DAF_COMP_ID}.sh.in ${CMAKE_CURRENT_BINARY_DIR}/configure_${DAF_COMP_ID}.sh @ONLY)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/configure_${DAF_COMP_ID}.sh DESTINATION bin)
    configure_file(install/cleanup_${DAF_COMP_ID}.sh.in ${CMAKE_CURRENT_BINARY_DIR}/cleanup_${DAF_COMP_ID}.sh @ONLY)
    install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/cleanup_${DAF_COMP_ID}.sh DESTINATION bin)
endif()

configure_file(${TEMPLATE_DIR}/DEBIAN/postinst.in  ${CMAKE_CURRENT_BINARY_DIR}/postinst @ONLY)
configure_file(${TEMPLATE_DIR}/DEBIAN/prerm.in  ${CMAKE_CURRENT_BINARY_DIR}/prerm @ONLY)
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_BINARY_DIR}/postinst;${CMAKE_CURRENT_BINARY_DIR}/prerm")

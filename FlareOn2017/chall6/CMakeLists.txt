cmake_minimum_required ( VERSION 2.8 )

project ( flare_chall6 )

# libs
# modules:
set ( M_PARSER "libpeconv/libpeconv" )

# modules paths:
set (PECONV_DIR "${CMAKE_SOURCE_DIR}/${M_PARSER}" CACHE PATH "PEConv main path")
add_subdirectory ( ${PECONV_DIR} )
set ( PECONV_LIB $<TARGET_FILE:libpeconv> CACHE FILE "PEConvLib library path" )

# Add sub-directories
#
add_subdirectory ( basic_ldr )
add_subdirectory ( peconv_basic_ldr  )
add_subdirectory ( peconv_autofill_ldr  )
add_subdirectory ( peconv_basic_sol )
add_subdirectory ( peconv_hooked_msgbox_sol )
add_subdirectory ( peconv_finished_sol )

#dependencies:
add_dependencies( peconv_basic_ldr libpeconv )
add_dependencies( peconv_autofill_ldr libpeconv )
add_dependencies( peconv_basic_sol libpeconv )
add_dependencies( peconv_hooked_msgbox_sol libpeconv )
add_dependencies( peconv_finished_sol libpeconv )

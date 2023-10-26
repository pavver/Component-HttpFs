idf_component_register(SRCS ""
                    INCLUDE_DIRS "include"
                    REQUIRES "bootloader_support spi_flash vfs fatfs"
                    PRIV_REQUIRES "spi_flash fatfs json Core"
                    )

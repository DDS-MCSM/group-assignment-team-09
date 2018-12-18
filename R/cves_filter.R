install.packages("net.security")

library("net.security")
library("stringr")

year <- "2018"

net.security::DataSetUpdate(samples = FALSE, use.remote = FALSE)

my_cves <- GetDataFrame("cves")

# Eliminar filas con "RESERVED" en la descripción
my_cves <- my_cves[!str_detect(my_cves$description, "RESERVED"),]

# Filtra los resultados buscando solo los cves del año 2018
my_cves <- my_cves[!str_detect(my_cves$cve, year),]

# Filtra cvss > 8
my_cves <- my_cves[my_cves$cvss > 8,]

destfile <-  tempfile(fileext = ".rda")

netsec <- download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda",
                        destfile = destfile)
load(destfile)
cves <- netsec.data$datasets$cves

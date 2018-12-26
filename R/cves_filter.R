#
# Team 09: CVE Parser
#
# Select CVEs appling year and score filters
#

# Install Dependencies, if needed
if (!suppressMessages(suppressWarnings(require("net.security", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("net.security")))
}
library("net.security")

library("stringr")

#Filter Parameters:
year <- "2018"
id_filter <- paste("CVE", year, sep="-")  # CVE-<year>
score_filter <- 8.0

######
#net.security::DataSetUpdate(samples = FALSE, use.remote = FALSE)
#filtered_cves <- GetDataFrame("cves")
#
## Eliminar filas con "RESERVED" en la descripción
#filtered_cves <- filtered_cves[!str_detect(filtered_cves$description, "RESERVED"),]
#
## Filtra los resultados buscando solo los cves del año 2018
#filtered_cves <- filtered_cves[!str_detect(filtered_cves$cve, year),]
#
## Filtra cvss > 8
#filtered_cves <- filtered_cves[filtered_cves$cvss > 8,]
#######

# Retrive latest datasets from github repository
destfile <-  tempfile(fileext = ".rda")
netsec <- download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda",
                        destfile = destfile)
load(destfile)
filtered_cves <- netsec.data$datasets$cves


# Filtra por año
filtered_cves <- filtered_cves[str_detect(filtered_cves$cve.id, id_filter),]

## Eliminar filas con "RESERVED" en la descripción
#filtered_cves <- filtered_cves[!str_detect(filtered_cves$description, "RESERVED"),]

# Filtra CVSS > 8
filtered_cves <- filtered_cves[(filtered_cves$cvss3.score > score_filter & !is.na(filtered_cves$cvss3.score)),]


## Muestra datos

# Grafica por svss3 score
#filtered_cves$cvss3.score
# Grafica por tipo de acceso
#filtered_cves$cvs2.av
# Grafica por CPE

# Severity vs Access Type

par(mfrow = c(3, 1), mar = c(4, 4, 2, 1))
hist(x = as.Date.POSIXlt(filtered_cves$published.date), col = "blue", breaks = "month", format = "%d %b %Y", freq = T, main = "CVE publication", xlab = "Publication date")




library(ggplot2)
install.packages("plotly")
library(plotly)
install.packages("gapminder")
library(gapminder)

p <- gapminder %>%
  # filtered_cves %>% group_by(filtered_cves$cvss2.av)
  ggplot( cves, aes_(cves$cvss3.av, cves$cvss3.score)) # +
  #ggplot( aes(x=cves$cvss3.av, y=cves$cvss3.score, color = continent, group=1)) +
  #geom_point() +
  #geom_line(size = 1) +
  #scale_x_log10() +
  #theme_bw()

p <- gapminder %>%
  ggplot( cves, aes(cves$cvss3.av, cves$cvss3.score), color = continent)

ggplotly(p)









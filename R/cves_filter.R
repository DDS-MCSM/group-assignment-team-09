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

if (!suppressMessages(suppressWarnings(require("stringr", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("stringr")))
}
library("stringr")

#Filter Parameters:
myfilters <- list(year = "2018",
                  id = "CVE-2018",  # CVE-<year>
                  score = 9.0)



# Retrive latest datasets from github repository
destfile <-  tempfile(fileext = ".rda")
netsec <- download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda",
                        destfile = destfile)
load(destfile)
filtered_cves <- netsec.data$datasets$cves


# Filtra por año
filtered_cves <- filtered_cves[str_detect(filtered_cves$cve.id, myfilters$id),]

## Eliminar filas con "RESERVED" en la descripción
#filtered_cves <- filtered_cves[!str_detect(filtered_cves$description, "RESERVED"),]

# Filtra CVSS > 9
filtered_cves <- filtered_cves[(filtered_cves$cvss3.score > myfilters$score & !is.na(filtered_cves$cvss3.score)),]


# Extraer porduct information: CPE from filtered_cves$vulnerable.configuration

df_cpes <- fromJSON(filtered_cves$vulnerable.configuration[1])


filtered_cves$affects[1]

library(jsonlite)

fromJSON(filtered_cves$affects)

fromJSON(paste0('[',toString(head(filtered_cves$affects)),']'))
fromJSON(paste0('[',toString(filtered_cves$affects),']'))


cbind(filtered_cves[,c("vendor_name","product_data")],fromJSON(paste0('[',toString(filtered_cves$affects),']')))
cbind(filtered_cves, fromJSON(paste0('[',toString(filtered_cves$affects),']')))

## Muestra datos

# Grafica por svss3 score
#filtered_cves$cvss3.score
# Grafica por tipo de acceso
#filtered_cves$cvs2.av
# Grafica por CPE
# Severity vs Access Type

# Muestra la Lista de CVEs por fecha de publicación
par(mfrow = c(3, 1), mar = c(4, 4, 2, 1))
hist(x = as.Date.POSIXlt(filtered_cves$published.date), col = "blue", breaks = "month", format = "%d %b %Y", freq = T, main = "CVE publication", xlab = "Publication date")


library(ggplot2)

filtered_cves$affects

ggplot(data.frame(filtered_cves), aes(x=filtered_cves$affects,fill=factor(filtered_cves$cvss2.av)))  +
  geom_bar() +
  coord_flip() +
  xlab("xlab") +
  ggtitle("title") +
  theme(
    legend.title=element_blank(),
    legend.position=c(.90,.1)
  )



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









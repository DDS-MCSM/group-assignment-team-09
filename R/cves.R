#******************************************************************************#
#                                                                              #
#                   Team 9 - Data Driven Security                              #
#                                                                              #
#                Juan Jose Sanz Martin - Alberto López Millán                  #
#                                                                              #
#******************************************************************************#

##
## CVE PARSER
##

# Select CVEs appling year and score filters
#

# Install Dependencies, if needed: net.security
if (!suppressMessages(suppressWarnings(require("net.security", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("net.security")))
}
library("net.security")

# Install Dependencies, if needed: stringr
if (!suppressMessages(suppressWarnings(require("stringr", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("stringr")))
}
library("stringr")


# Install Dependencies, if needed: jsonlite
if (!suppressMessages(suppressWarnings(require("jsonlite", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("jsonlite")))
}
library("jsonlite")


# Install Dependencies, if needed: ggplot2
if (!suppressMessages(suppressWarnings(require("ggplot2", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("ggplot2")))
}
library("ggplot2")




### Retrive latest datasets from github repository: net-security

RetrieveCVEs <- function(){

  destfile <-  tempfile(fileext = ".rda")
  netsec <- download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda",
                          destfile = destfile)
  load(destfile)
  df_cves <- netsec.data$datasets$cves

  return(df_cves)
}

### Filter CVEs by year

FilterCVEsByYear <- function(df, year_filter){

  cve_id_filter = paste0("CVE-", year_filter)    # CVE-<year>

  # Filtra por año
  filtered_cves <- df[str_detect(df$cve.id, cve_id_filter),]

  ## Remove NAs
  #filtered_cves <- filtered_cves[!(is.na(filtered_cves$cve.id)),]

  return(filtered_cves)
}

### Filter CVEs by Access Vector
FilterCVEsByAccessVectorNetwork <- function(df){

  av_filter_exact <- "^NETWORK$"
  # Filtra por Acces Vector
  filtered_cves <- df[str_detect(df$cvss3.av, av_filter_exact),]

  ## Remove NAs
  #filtered_cves <- filtered_cves[!(is.na(filtered_cves$cvss3.av)),]

  return(filtered_cves)
}


### Filter CVEs by Score

FilterCVEsByScore <- function(df, score_filter){


  # Filtra CVSS > score_filter  (default >= 8 )
  filtered_cves <- df[(df$cvss3.score >= score_filter),]

  ## Remove NAs
  #filtered_cves <- filtered_cves[!(is.na(filtered_cves$cvss3.score)),]

  return(filtered_cves)
}

### Filter NA Values in important columns
FilterNAs <- function(df){

  # Elimina los items que contengan NAs en las siguientes columnas
  # df$cvss3.av
  # df$cvss3.score
  # df$vulnerable.configuration
  df <- df[!(is.na(df$cve.id)) | !(is.na(df$cvss3.av)) | !(is.na(df$cvss3.score)) | !(is.na(df$vulnerable.configuration)),]

  return(df)
}


PlotCVEsByPublishedDate <- function(df) {

  # Muestra la Lista de CVEs por fecha de publicación
  par(mfrow = c(3, 1), mar = c(4, 4, 2, 1))
  hist(x = as.Date.POSIXlt(df$published.date), col = "blue", breaks = "month", format = "%d %b %Y", freq = T, main = "CVE publication", xlab = "Publication date")

}

PlotPieChartCVEsByScore <- function(df) {

  plot_data <- as.data.frame(table(cves$cvss3.score))
  colnames(plot_data) <- c('score', 'count')

  ggplot(plot_data, aes(x='',y=count, fill=as.factor(score))) +
    geom_bar(stat="identity", width=1) +
    coord_polar("y", start=0) +
    labs(fill="Score") +
    ggtitle("CVEs por score") +
    theme(
      #legend.title=element_blank(),
      axis.title.x = element_blank(),
      axis.title.y = element_blank(),
      axis.text.x = element_blank(),
      axis.text.y = element_blank(),
      axis.ticks.x = element_blank(),
      axis.ticks.y = element_blank()
    )

  # Muestra CVEs por Score
  #ggplot(df, aes(x="", y=cvss3.score, fill=factor(cvss3.score))) +
  #  geom_bar(stat="identity", width=1) +
  #  coord_polar("y", start=0) +
  #  labs(fill="Score") +
  #  ggtitle("CVEs por score") +
  #  theme(
  #    #legend.title=element_blank(),
  #    axis.title.x = element_blank(),
  #    axis.title.y = element_blank(),
  #    axis.text.x = element_blank(),
  #    axis.text.y = element_blank(),
  #    axis.ticks.x = element_blank(),
  #    axis.ticks.y = element_blank()
  #  )

}

ExtractCPE <- function(cve_df){

  # Extract product information: CPE from cves$vulnerable.configuration

  # CVEs ID + CPEs and create a data frame
  cve_id_col <- cve_df[ , +which(names(cve_df) %in% c("cve.id"))]
  cpe_column <- lapply(cve_df$vulnerable.configuration, jsonlite::fromJSON)

  # CPE      cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
  # Official CPE schema specify this regex: cpe:2.3:aho*-{5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^{\|}~]))+(\?*|*?))|[*-])){4}
  # El siguiente RegEx, es el oficial de CPE añadiendo un "escape" \ adicional para que funcione en R
  #             cpe:2.3:aho*-{5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^{\|}~]))+(\?*|*?))|[*-])){4}
  #cpe_regex <- "cpe:2.3:aho*-{5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\\*\\-]))(:(((\\?*|\\*?)([a-zA-Z0-9\\-\\._]|(\\\\[\\\\\\*\\?!"#$$%&'\\(\\)\\+,/:;<=>@\\[\\]\\^{\\|}~]))+(\\?*|*?))|[*-])){4}"
  #cpe_regex <- "(cpe:[a-zA-Z0-9:_-.*]+)"   # RegEx "cpe:" + Alphanum + : + : + underscore (_) + *
  #cpe_regex <- "(cpe:[0-9](\.[0-9]+)?:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+:[^:a-zA-Z0-9_\*]+"
  #cpe_regex <- "cpe:2.3:([a-z]):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+)\""
  cpe_regex <- "cpe:([0-9]\\.[0-9]+?):([a-z]):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):"
  cpes_parsed <- str_match( cpe_column, cpe_regex)
  #cpes_parsed <- str_match( cpe_column, pattern = cpe_regex)

  # List of Unique CPEs:
  #unlist(cpes_parsed) %>% unique
  #lapply(cpes_parsed, unique)


  cpe_df <-  as.data.frame(cbind(cve_id_col,cpe_column,cpes_parsed))


  colnames(cpe_df) <- c('cve.id', 'vulnerable.configuration', 'cpe23Uri','CPE_version', 'Part_Component', 'Vendor_Component', 'Product_Component', 'Version_Component', 'Edition_Component', 'Language_Component', 'Abbreviations')

  return(cpe_df)

}

FilterCPEsByPartComponent <- function(df, regex) {

  # Filtra CPES PArt Component with regex expresion
  filtered_cpes <- df[str_detect(df$Part_Component, regex),]

  return(filtered_cpes)
}


PlotCPEssByVendor <- function(df) {

  # library(ggplot2)
  #
  # ggplot(data.frame(df), aes(x=factor(df$Product_Component),fill=factor(df$Vendor_Component)))  +
  #   geom_bar() +
  #   coord_flip() +
  #   xlab("Dominio") +
  #   ggtitle(paste0("Vulnerabilidades según Vendor_Component")) +
  #   theme(
  #     legend.title=element_blank(),
  #     legend.position=c(.90,.1)
  #   )
  #
  #
  #
  #   ggplot(cpes, aes(x=cpes$Product_Component)) +
  #     coord_flip() +
  #     geom_histogram(binwidth=0.5, aes(fill=..count..))
  #
  #
  #
  #     geom_bar(stat="count")

}

####################################################
####################################################
#### TESTs y pruebas a integrar en funciones


test <- function(){



  cpe_df$cpe_column





  cve_id_col <- cves_score_10[ , +which(names(cves_score_10) %in% c("cve.id"))]
  cpe_column <- lapply(cves_score_10$vulnerable.configuration, jsonlite::fromJSON)
  cpe_df <- as.data.frame(cbind(cve_id_col,cpe_column))


  remove(cpes)
  cpes <- data.frame(operator=character(), cpe_match=character(), vulnerable=character(), cpe23Uri=character())


  for(i in 1:nrow(cves_score_10)){
    cpes[i,] <- NA
    #print(paste(i,"-", cves_score_10$vulnerable.configuration[i]))
    cpe_tmp <- fromJSON(cves_score_10$vulnerable.configuration[i])
    cpe_tmp$operator
    cpe_tmp$cpe_match

    cpes[i,]$operator
    cpes[i,]$operator <- paste0("[", toString(cpe_tmp$operator) ,"]")   # OR ? AND ?

    tmp <- str_match(cpe_tmp$cpe_match, "cpe:2.3:o:([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+)\\\",")

    #print(paste(i, tmp))
    cpes[i,]$cpe_match <- toString(tmp)

    unlist(fromJSON(cves_score_10$vulnerable.configuration[1]),recursive = TRUE, use.names = TRUE)
    cves$vulnerable.configuration <- unlist(lapply(cve.entries$configurations$nodes, jsonlite::toJSON))

    test <- lapply(cves_score_10$vulnerable.configuration, jsonlite::fromJSON)
    test2 <- lapply(test, as.data.frame)
    test[21]

    list(test[1])

    test2 <- unlist(test,recursive = TRUE,use.names = TRUE)

    cves_score_10$vulnerable.configuration[21]

    df <- data.frame(matrix(unlist(test), nrow=length(test), byrow=T))



  }


#df_cpes <- ""
#fromJSON(filtered_cves$vulnerable.configuration[1])
#list_cpes <- ""
#fromJSON(toString(head(filtered_cves$vulnerable.configuration)))
#
#filtered_cves$vulnerable.configuration[1]
#extract(list_cpes[3], '([^/]+)/.*', remove=FALSE)
#gsub('.*\'(cpe.*)\'',list_cpes[2])
#gsub("^.*(cpe)","", toString(list_cpes[2]))
#stringr::str_extract(string = filtered_cves$vulnerable.configuration[1], pattern = ".*\"(cpe:.*)\".*")

#filtered_cves$affects[1]
# ----------------------------

cpes <- fromJSON(cves$vulnerable.configuration[1])
cpes <- fromJSON(toString(cves$vulnerable.configuration[1]))
# cpes[['cpe_match']][['vulnerable']]
# cpes[['cpe_match']][['cpe23Uri']]
cpes$operator   # OR ? AND ?
cpes_match <- cpes$cpe_match
str_detect(cpes_match, "TRUE")
grep("TRUE", cpes_match, value = TRUE)
#regexpr("(cpe:2.3:.*)", cpes_match)
str_match( cpes_score_10$vulnerable.configuration, "cpe:2.3:o:([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):([^:]+)\\\",")






# cpe:2.3:o:juniper:junos:14.1:r1:*:*:*:*:*:*
# o:<vendor>:<product>:<version>:<release>


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






}




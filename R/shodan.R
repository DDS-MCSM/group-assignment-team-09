#******************************************************************************#
#                                                                              #
#                   Team 9 - Data Driven Security                              #
#                                                                              #
#                Juan Jose Sanz Martin - Alberto López Millán                  #
#                                                                              #
#******************************************************************************#

##
## SHODAN.IO FUNCTIONS
##

# Install Dependencies, if needed: devtools
if (!suppressMessages(suppressWarnings(require("devtools", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("devtools", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(devtools)

# Install Dependencies, if needed: shodan   ---    R Shodan Lib: https://github.com/hrbrmstr/shodan
if (!suppressMessages(suppressWarnings(require("shodan", quietly = T)))) {
  suppressMessages(suppressWarnings(devtools::install_github("hrbrmstr/shodan")))
}
library(shodan)

# Install Dependencies, if needed: ggplot2
if (!suppressMessages(suppressWarnings(require("ggplot2", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("ggplot2", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(ggplot2)

# Install Dependencies, if needed: ggthemes
if (!suppressMessages(suppressWarnings(require("ggthemes", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("ggthemes", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(ggthemes)

# Install Dependencies, if needed: rworldmap
if (!suppressMessages(suppressWarnings(require("rworldmap", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("rworldmap", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(rworldmap)


### Add Shodan Key

AddShodanKey <- function() {
  # Check Shodan Key: it should be stored in .Renviron file
  if ( !file.exists("~/.Renviron") ) {
    warning("Shodan Key not set")
    #shodan_key<-readline(prompt="Provide Shodan Key: " )
    cat("Please Add Key ... \nSHODAN_API_KEY = \"<key>\"")
    usethis::edit_r_environ()
  }

  if ( ! nchar(Sys.getenv("SHODAN_API_KEY")) > 1 ) {
    warning("SHODAN_API_KEY not found")
    cat("Please Add Key ... ")
    usethis::edit_r_environ()
  }

  # To see Shodan Key run: Sys.getenv("SHODAN_API_KEY")
}



### Obtener informacion de Shodan de un Producto y Version

GetShodanResults <- function(vendor, product, version){

  #vendor="juniper"
  #product="junos"
  #version="14.1x53"

  # Set query
  result <- shodan_search(query=paste(vendor,product,version,sep = "+"))
  df = result$matches

  return(df)
}


### Representar informacion de Shodan en Mapa

PlotMapShodanResults <- function(df){

  world = map_data("world")
  (ggplot() +
      geom_polygon(data=world, aes(x=long, y=lat, group=group)) +
      geom_point(data=df, aes(x=df$location$longitude, y=df$location$latitude), colour="#EE760033",size=1.75) +
      labs(x="",y="") +
      theme_few())

}











install.packages("xtable")
install.packages("maps")
library(plyr)  # ddply
library(xtable)
library(maps)






vendor="juniper"
product="junos"
version="14.1x53"

# Set query
result <- shodan_search(query=paste(vendor,product,version,sep = "+"))
df = result$matches

###############################################################################
#################################################################################
#
# --> https://rud.is/b/2013/01/17/shodan-api-in-r-with-examples/





##################
##################
##################

#(facets = NULL, page = 1, minify = TRUE)
#find the first 100 found memcached instances
#result = SHODANQuery(query='port:11211',limit=100,trace=TRUE)


# aggregate result by operating system
# you can use this one if you want to filter out NA's completely
#df.summary.by.os = ddply(df, .(os), summarise, N=sum(as.numeric(factor(os))))
#this one provides count of NA's (i.e. unidentified systems)
df.summary.by.os = ddply(df, .(df$os), summarise, N=length(df$os))

# sort & see the results in a text table
df.summary.by.os = transform(df.summary.by.os, os = reorder(os, -N))
df.summary.by.os
# plot a bar chart of them
(ggplot(df.summary.by.os,aes(x=os,y=N,fill=os)) +
    geom_bar(stat="identity") +
    theme_few() +
    labs(y="Count",title="SHODAN Search Results by OS"))







###############################################################################
#################################################################################
#
# --> https://rud.is/b/2013/01/17/shodan-api-in-r-with-examples/

# sort & view the results by country
# see above if you don't want to filter out NA's
df.summary.by.country_code = ddply(df, .(df$location$country_code, df$location$country_name), summarise, N=sum(!is.na(df$location$country_code)))
df.summary.by.country_code = transform(df.summary.by.country_code, country_code = reorder(df$location$country_code, -N))

df.summary.by.country_code

# except make a choropleth
# using the very simple rworldmap process
shodanChoropleth = joinCountryData2Map( df.summary.by.country_code, joinCode = "ISO2", nameJoinColumn = "country_code")
par(mai=c(0,0,0.2,0),xaxs="i",yaxs="i")
mapCountryData(shodanChoropleth, nameColumnToPlot="N",colourPalette="terrain",catMethod="fixedWidth")

###############################################################################
#################################################################################

# find all Cisco IOS devies that may have an unauthenticated admin login
# setting trace to be TRUE to see the progress of the query
#result = shodan_search(query="cisco last-modified www-authenticate", facets = NULL, page = 1, minify = TRUE)

#find the first 100 found memcached instances
result = shodan_search(query='port:11211')

df = result$matches

# aggregate result by operating system
# you can use this one if you want to filter out NA's completely
#df.summary.by.os = ddply(df, .(os), summarise, N=sum(as.numeric(factor(os))))
#this one provides count of NA's (i.e. unidentified systems)
df.summary.by.os = ddply(df, .(os), summarise, N=length(os))

# sort & see the results in a text table
df.summary.by.os = transform(df.summary.by.os, os = reorder(os, -N))
df.summary.by.os




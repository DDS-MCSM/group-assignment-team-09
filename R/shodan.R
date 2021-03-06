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

# Install Dependencies, if needed: maps
if (!suppressMessages(suppressWarnings(require("maps", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("maps", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(maps)


# Install Dependencies, if needed: plyr
if (!suppressMessages(suppressWarnings(require("plyr", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("plyr", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(plyr)

# Install Dependencies, if needed: xtable
if (!suppressMessages(suppressWarnings(require("xtable", quietly = T)))) {
  suppressMessages(suppressWarnings(install.packages("xtable", repos = "http://cran.rstudio.com/", quiet = T, dependencies = T)))
}
library(xtable)




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


### Create Query Text Column for Shodan
CPE_Create_Shodan_Query_Column <- function(df) {

  # Create Shodan Query as : Vendor+Pruduct+Component
  df$ShodanQuery <- paste(df$Vendor_Component,df$Product_Component,df$Version_Component,sep = "+")

  # Filter Query Text: Remove "*"
  df$ShodanQuery <- stringr::str_remove_all(df$ShodanQuery, "\\*")
  df$ShodanQuery <- stringr::str_replace_all(df$ShodanQuery, "_", "+")  # treat undescore  as an space
  #df$ShodanQuery <- stringr::str_remove_all(df$ShodanQuery, "\+-")   # Remove problematic fields
  #df$ShodanQuery <- stringr::str_remove_all(df$ShodanQuery, "+$")
  # Remove problematic fields:
  df$ShodanQuery  <- gsub("+$","" , df$ShodanQuery ,ignore.case = TRUE)
  df$ShodanQuery  <- gsub("+-$","" , df$ShodanQuery ,ignore.case = TRUE)

  return(df)
}

### Obtener informacion de Shodan de un Producto y Version

GetShodanResults <- function(query_text){

  #vendor="juniper"
  #product="junos"
  #version="14.1x53"


  # Set query
  result <- shodan_search(query=query_text)


  #if (result$total > 0) {
  #  df_res <- result$matches
  #}
  #else {
  #  df_res <- NA
  #}


  return(result)
}

CPE_Shodan_Search <- function(df, i_init, i_end){

  #####
  #####

#num_cpes <- nrow(cpes)
#shodan_cpe_results <- cpes[0,]
#for(i in 1:nrow(cpes))
#for(i in 1:10) {
#  shodan_cpe_results[c(i),] <-  CPE_Shodan_Search(cpes[c(i),])
#}
#shodan_cpe_results <- CPE_Shodan_Search(cpes)
#########
#########



  # #shodan_cpe_results <- CPE_Shodan_Search(cpes, forceShodanQuery = FALSE)
  # #shodan_cpe_results <-  CPE_Shodan_Create_Empty_DF(cpes)
  # remove(shodan_cpes_results)
  # i_init <- 1
  # i_end  <- 10
  # #shodan_cpes_results <- CPE_Shodan_Search1(cpes)
  # for(i in i_init:i_end) {
  #
  #   #results <- shodan_search(query=df$ShodanQuery[1])
  #   i <- 1
  #   ### Test con i = 4 ####
  #   print(paste("Query:", i, cpes$ShodanQuery[i]))
  #
  #   results <- GetShodanResults(query=cpes$ShodanQuery[i])
  #
  #   print(paste("Num of results: ", results$total))
  #
  #   cbind(cpes[c(i),],  results )
  #
  #   tmp_row <- rbind(cpes[c(i),])
  #   tmp_row$ShodanResultsTotal <- as.integer(results$total)
  #
  #   if( results$total > 0) {
  #     tmp_row <- cbind(tmp_row,as.data.frame(results$matches))
  #   }
  #
  #   shodan_cpes_results <- rbind(cpes[c(i),], tmp_row,  fill=TRUE)
  #   remove(tmp_row)
  #   #tmp_row$shodan_results <- results
  #
  #   #test2 <- cbind(cpes[c(4),],results$matches)
  #
  #
  #   # Agrega fila al data frame final
  #   #shodan_cpe_results <- rbind(tmp_row)
  #   #if(result$total == 0) {
  #   #shodan_cpes_results <- rbind(cbind(cpes[c(i),]))
  #   #}
  #   #else {
  #   #  shodan_cpes_results <- rbind(cbind(cpes[c(i),],results$matches))
  #   #}
  #
  #
  #
  #   Sys.sleep(1)

  # Old code:  shodan_cpe_results <-  CPE_Shodan_Search(cpes, i_init = 1, i_end = 10)

  #df$shodan_result <- list(nrow(df))
  #df$shodan_total <- matrix(integer(0),nrow = nrow(df))
  #df$shodan_matches <- list(nrow(df))

  for(i in i_init:nrow(df)) {
    # Debug
    print(paste("Query:", i, df$ShodanQuery[i]))

    #df$shodan_results[i] <- data.frame(GetShodanResults(df$ShodanQuery[i]))
    #df$shodan_results[i] <- GetShodanResults(df$ShodanQuery[i])
    result <- shodan_search(query=df$ShodanQuery[i])

    #df$shodan_result[[i]] <- result
    df$shodan_total[[i]] <- result$total
    if ( result$total > 0 )
    {
      df$shodan_matches[[i]] <- list(result$matches)
    }
    else
    {
      df$shodan_matches[[i]] <- NA
    }

    #res_tmp_df<-data.frame(result$total,as.data.frame(result$matches))
    #rbind(results_df, res_tmp_df)

    #df$shodan_total[i] <- result$total
    #if ( result$total > 0 ){ df$shodan_matches[i] <- result$matches }
    #else                   { df$shodan_matches[i] <- NA}

    Sys.sleep(1)


    if ( i >= i_end ) {
      break
    }

    # Debug results
    #suppressMessages(suppressWarnings( print(df$shodan_results[i]) ))
  }

  return(df)
}


# Funcion corregida por de Humbert
CPE_Shodan_Search1 <- function(df) {
  set.seed(666)
  df <- df[sample(1:nrow(df), 20), ]


  df <- apply(df, 1,
              function(x){
                # Sleep
                Sys.sleep(2)

                # Shodan query
                #print(paste("Query:", x["ShodanQuery"]))
                result <- shodan::shodan_search(query = x["ShodanQuery"])
                #print(paste("Num of results: ", result$total))
                if (result$total > 0) {
                  cpe.ips <- result$matches
                  location <- cpe.ips$location
                  cpe.ips <- cpe.ips[,!(sapply(cpe.ips[1,], class) %in% c("list", "data.frame"))]
                  cpe.ips$cpe23Uri <- rep(x = x["cpe23Uri"], nrow(cpe.ips))
                  cpe.ips <- dplyr::bind_cols(cpe.ips, location)
                  cpe.ips <- dplyr::left_join(as.data.frame(t(x)), cpe.ips, by = "cpe23Uri")
                  cpe.ips
                } else {
                  NA
                }

              })
  df <- df[!is.na(df)]
  df <- dplyr::bind_rows(df)
  return(df)
}

### Representar informacion de Shodan en Mapa

PlotMapShodanResults <- function(df){

  world = map_data("world")
  (ggplot() +
      geom_polygon(data=world, aes(x=long, y=lat, group=group)) +
      geom_point(data=df, aes(x=df$matches.location$longitude, y=df$matches.location$latitude), colour="#EE760033",size=1.75) +
      labs(x="",y="") +
      theme_few())


}

PlotMapShodanCPEResults <- function(df){

  world = map_data("world")
  (ggplot() +
      geom_polygon(data=world, aes(x=long, y=lat, group=group)) +
      geom_point(data=df, aes(x=longitude, y=latitude), colour="#EE760033",size=1.75) +
      labs(x="",y="") +
      theme_few())


}






####################################################
####################################################
#### TESTs y pruebas a integrar en funciones


other <- function() {









vendor="juniper"
product="junos"
version="14.1x53"

# Set query
result <- shodan_search(query=paste(vendor,product,version,sep = "+"))
df <- result$matches



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

}


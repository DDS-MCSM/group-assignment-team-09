install.packages("devtools")
install.packages("ggplot2")
install.packages("xtable")
install.packages("maps")
install.packages("rworldmap")
install.packages("ggthemes")
devtools::install_github("hrbrmstr/shodan")

library(shodan)
library(ggplot2)
library(xtable)
library(maps)
library(rworldmap)
library(ggthemes)




# R Shodan Lib: https://github.com/hrbrmstr/shodan

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



# Set query
result <- shodan_search(query="SMB", facets = NULL, page = 1, minify = TRUE)

# Aggregate by OS
df <- result$matches
df.summary.by.os <- ddply(df, .(os), summarise, N=length(.os))


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




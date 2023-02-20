# BashAPI

Like wasabi, only with b, h and p. 
This is a simple bash api gateway. It is based on [sampo](https://github.com/jacobsalmela/sampo) and adds some extra functions, like parsing the headers and body.  
There is still a few more things to add, like proper body parsing (i.e. JSON) and returning proper status codes instead of just 200.

## License

MIT License

## Motiviation

Currently we needed a simple callback uri to execute a shellscript, so we stumbled over sampo.  
While it was pretty great, we also needed a way to parse the uri properly to pass parameters to a shellscript.  
With other webservers you might use CGI and add some Lua components and so on, so this seemed to be a very simple solution to our problem.  

As this is very simple and also requires a very low amount of resources, there are already considerations to use it as a base for something more :).  

## Usage

You can run it directly as it is or build a Docker image and run it.  
like:

```bash
socat TCP-LISTEN:9900,reuseaddr,fork system:bashapi.sh
```
You can replace the port with whatever you see fit.  

With a container image, you can start your container like this:  
```bash
docker run -p 9900:9900 bashapi
```

## Configuration and Options

The application can be run with various options and additional environment variables.  
If you need global environment vars for your script, just add `BASHAPI_GLOBAL_VARNAME=value`.  
For variables scoped to the called script, add variables named `BASHAPI_SCRIPTNAME_VARNAME=value`.   

### Extending

Now there is the fun part. You can add multiple paths and scripts to the `api/` directory (or even somewhere else if you add more options to the `bashapi.conf` file).  
Create whatever script you like, put it into `api/` directory and just run a request against the endpoint with your scriptname.  
For more information, check `api/example` on usage.  

## Notes

Since it mostly executes shellscripts and other commands, it is not advised to use this as a public endpoint.  
If you need to secure it, use a webproxy in front of it that provides the appropriate mechanisms like TLS, mTLS, OIDC, Basic Auth etc.  
Its not meant to run as something public and more as a convienient tool to help you to provide an API for some tasks that need to performed internally.  

## TODOs:

- The response with 200 all the time seem inappropriate, so this requires some consideration and refactoring.
- While the body is now parsed, it also needs to be properly handled and using different ways to do so (i.e. JSON, x-form-urlencoded)
- Add some conventions on how the scripts are executed or what functions are available
- Maybe some minimalistic UI on the root path to show help or whatsoever
- Add some default behavior
- Use maybe some external library that will be sourced as default exist
- Be able to run scripts asynchronously
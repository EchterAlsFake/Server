# What's this?
This is the official server for Porn Fetch, handling payment flows :) 

**https://echteralsfake.me**

### What does it do? 
- Serves as a test for myself
- Update checking for Media Archiver
- Error / Feedback reporting for Media Archiver
- Local API Tests for my Media APIs
- Landing page

### Cloudflare
The server is protected by cloudflare and uses the IPv4 to IPv6 proxy tunnel, because Vodafone gives customers only
a public IPv6 adress. Cloudflare DOES collect your IP adress and uses it for fraud / abuse protection. You can find more information [HERE](https://www.cloudflare.com/de-de/privacypolicy/)
Please note, that my server itself does absolutely ZERO logging of your data unless you explicitly agree on it. 
My website also does not embed any third party fonts or cookies that could track you. 


### Where and how?
- In my own home 24/7 
- 1gbp/s download, 50mbit/s upload (Ethernet)
- Running on an Acer Swift 3 (4c 8t, 8GB RAM)
- Powered by Arch Linux 

### Endpoints
- /download -> Download Media Archiver
- /stats -> View real-time server stats
- / -> Landing page
- /feedback -> Report feedback anonymously
- /ping -> Ping the server
- /update -> Fetch update information for Media Archiver
- /report -> Report errors 
- /ci -> personal endpoint for API tests
- /buy_license -> You can buy a license for Media Archiver here

> [!WARNING]
> The `/buy_license` endpoint is ONLY a test environment. You won't be charged
> and you won't receive a valid license. Please don't use this endpoint yet.
> It's just for experimenting and testing. I'll tell you when it's ready...


![Progress](http://[::1]:8000/checklist/progress.svg)

### Data collection?
- No IP
- Strict Zero Log policy
- German / EU privacy protecting you
- No NGINX Remote Address copying
- No debug information

### Why? 
Because I want to have full control all the time about the data being stored,
the device hosting it and I want to learn a little bit by doing it myself.

### What about IPv4
Ask Vodafone to get me an IPv4, then I can enable it ;) 

### Future Plans? 
- [x] Own Domain (Namecheap)
- [x] A real SSL certificate
- [] More endpoints for more projects
- [x] License server for Media Archiver
- [x] Better I/O handling and saving of reports / errors
- [x] IPv4 support (I try to ask Vodafone kindly)
- [] Backup using my Tablet in case main server is down (don't know if that works though)




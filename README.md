# Short-URLs-checker

This implementation was developed using Python 3 in Linux environment. 
The main features that are implemented are:
- expand short URLs (from providers like bit.ly, tinyurl, goo.gl, etc) by POST requesting the [checkshorturl](http://checkshorturl.com/) services.
- multiprocessing support for URL expanding (in my test cases, at least 4 times faster than the sequential method).
- check the expanded URLs against the [Google Safe Browsing](https://developers.google.com/safe-browsing) service using it's API.
- check the expanded URLs against the multi.uribl.com blacklist domain checker using [pydnsbl](https://pypi.org/project/pydnsbl/).
- add support for searching .eml files for short URLs

### Installation
To install pydnsbl
```bash
pip3 install pydnsbl
```

### Usage
To run the script
```bash
python3 urls.py <input_type> <file_name>
```
- input_type can be 0 (to read the list of the URLs from a .txt file) or 1 (to parse a .eml file and find the list of URLs in it).
- file_name is the actual name of the file

#### Examples
To run the URLs checker on short_urls.txt file that contains a list of URLs.
```bash
python3 urls.py 0 short_urls.txt
```

To run the URLs checker on mail.eml file that contains a mail.
```bash
python3 urls.py 1 mail.eml
```

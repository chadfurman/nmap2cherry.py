# Nmap2cherry.py 

A python script inspired by [this hacky XSLT](https://github.com/CBonnell/nmap2cherry)

Generate a new_cherrytree.ctd file from nmap.xml output!

## Installation

Use [git](https://guides.github.com/introduction/git-handbook/) to clone down the repository locally as follows:

```bash
git clone https://github.com/chadfurman/nmap2cherry.py.git
```

## Usage

Run nmap2cherry.py using python3 and passing the path to your nmap.xml file (nmap -oX path ...)

```bash
cd nmap2cherry.py/
python3 nmap2cherry.py /path/to/nmap.xml
cherrytree new_cherrytree.ctd # optional step to launch cherrytree on the newly created .ctd file
```

## Tests

Tests help make sure that when you change the code, everything still works as expected.

This project strives for test-coverage of most if not all functionality.

Running the tests is easy, as they use the built-in unittest module:

```bash
cd nmap2cherry.py
python3 nmap2cherry.test.py
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)

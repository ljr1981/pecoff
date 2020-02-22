# PECOFF
Library to detect MS Windows image file types

## Purpose
There is a need in both Windows and Linux to understand if an image file (e.g. DLL, LIB, etc) is designed for a particular processor and so on. My original question was: "Is this LIB file 32 or 64 bits?" One way to answer that question in MS Windows is to parse the file structure based on the PE specification and answer the question using the COFF header data. The specific answer is found in the 'machine' data.

## Overview
In this very small library are two classes. Only the PE_IMAGE_FILE class is needed to parse image files and derive answers to questions using the data contained in various headers and sections.

A second class, PE_DATA (and its companion PE_DATA_SPECS) is a convenience class. It is there to offer a data repository solution for storing data collected from many image files in a SQLite3 database. The idea is to have a ready-made data repo where one can store information collected with PD_IMAGE_FILE objects and retrieve that information quickly from a database rather than the long and painful process of rummaging through the file system each time one wants some basic answers for many scanned files.

## PE_IMAGE_FILE
Presently, there is but one creation feature for this class: 'make', which takes a single argument. This argument needs at least `a_file_name', but can also be pre-pended with a relative or full file path.

The creation procedure will load the file and process it, determining first if the file is a PE candidate image file. If not, processing (or scanning) stops. The 'file_name' and 'directory' will be populated, but all other COFF header information will be 0 (empty).

If the file is a PE image, then the COFF header will be located and parsed, its values (some of them) will be set in the appropriate data features of the object.

Note that there will also be some information stored about the file based on the MS Windoows file system that is not taken directly from the PE COFF header, but is generalized FILE_INFO of interest. The PE_DATA class will store some of this information for your convenience to be used for SQL SELECT queries later on as you have need.

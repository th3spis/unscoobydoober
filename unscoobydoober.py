#Checks for specific icons (from specific directory) inside the resources section in PE files

import os
import pefile
import binascii
import sys

binary_filename=sys.argv[1]
iconsdirectory = 'MSOicons'

def read_content(fname):
  #open handle to read file bytes
  f = open(fname, "rb")
  #read file bytes
  file_content=f.read()
  #print(file_content)
  f.close()
  return file_content


#Check every if any icon in testicons directory is found in the resources section of binary_filename
def icon_checker(rsc_data, icons_directory):
  # iterate over icons in testicons directory and subdirectories
  for root, dirs, files in os.walk(icons_directory):
      for filename in files:
        icon_path=os.path.join(root, filename)
        icon_data=read_content(icon_path)
        #Look for current icon in the given resource data
        if(rsc_data in icon_data):
          print("Found PE file with MS-Office Icon.")
          return True

#Get the icons from the resources section of the PE file
#(mostly from the pe module documentation (for string objects in resources))
def binary_digger(pe_bin):
  iconfound=False
  pe = pefile.PE(pe_bin)
  #Get indexes for icon directory entries
  rt_icon_idx = [
    entry.id for entry in 
    pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE['RT_ICON'])

  # Get the icon directory entries of PE file
  rt_icon_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_icon_idx]
  print("Found " + str(len(rt_icon_directory.directory.entries)) + " icon directory entries in file " + pe_bin + ".\n")
  # For each of the entries (which will each contain a block of 16 icons)
  i=0
  for entry in rt_icon_directory.directory.entries:
    # Get the RVA of the icon data and size of the icon data
    data_rva = entry.directory.entries[0].data.struct.OffsetToData
    size = entry.directory.entries[0].data.struct.Size
    #Retrieve the actual data and start processing the icons
    data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
    print("\tChecking icon " + str(i) + " in resources.\n")
    iconfound=icon_checker(data, iconsdirectory)
    if(iconfound):
      break
    i=i+1

binary_digger(binary_filename)

import io, zipfile

def read_file_content(file):
    file_data = io.BytesIO()
    file.seek(0)
    file_data.write(file.read())
    return file_data

def create_zip_buffer(files_dict):
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        for file_name, file_content in files_dict.items():
            zip_file.writestr(file_name, file_content)
    zip_buffer.seek(0)
    return zip_buffer

    

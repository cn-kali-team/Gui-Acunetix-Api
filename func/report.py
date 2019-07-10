def save_to_md(tree_view, file_path):
    print(file_path)
    model = tree_view.get_model()
    for row in model:
        print(row[1])

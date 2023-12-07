import hashlib

def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def mot_de_passe_genere(min=True, maj=True, chif=True, cs=True):
    alphabets = ''

    if min:
        alphabets += 'abcdefghijklmnopqrstuvwxyz'

    if maj:
        alphabets += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

    if chif:
        alphabets += '0123456789'

    if cs:
        alphabets += r'%_!$^&#()[]=@./-+,;*:'

    if len(alphabets) < 8:
        raise ValueError("Il doit contenir au moins huit caractères.")

    while True:
        try:
            user_password = input("Veuillez saisir votre mot de passe avec 8 caractères: ")

            if len(user_password) < 8:
                raise ValueError("Le mot de passe doit avoir au moins huit caractères.")

            if all(cs in alphabets for cs in user_password):
                hashed_password = hash_password(user_password)
                print("Mot de passe valide et crypté : ", hashed_password)
                break
            else:
                raise ValueError("Le mot de passe doit contenir au moins un caractère de chaque type sélectionné.")
        except ValueError as e:
            print("Erreur, mot de passe non valide:", e)

mot_de_passe_genere()

































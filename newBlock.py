from block import *
import datetime as dt
from cs50 import SQL

db = SQL("sqlite:///user.db")

def next_block(last_block, data):
    this_index = last_block.index + 1
    this_timestamp = dt.datetime.now()
    # A one level deep copy of data has been created since data is modified repeatedly
    # in the calling function and if data is a direct pointer, it leads to modification
    # of old data in the chain.
    this_data = data[:]
    this_prev_hash = last_block.hash
    return Block(this_index, this_timestamp, this_data, this_prev_hash)

def add_block(c, blockchain):
    data = []
    rows = db.execute("SELECT * FROM registrations WHERE class_name = :class_name", class_name=c)
    for row in rows:
        data.append((dt.datetime.today().strftime('%Y-%m-%d'), row["student_name"], row["status"]))
    previous_block = blockchain[-1]
    block_to_add = next_block(previous_block, data)
    blockchain.append(block_to_add)

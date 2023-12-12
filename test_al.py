import numpy as np
from datetime import datetime
# sorted_pair1 = sorted([('192.168.127.130', '5000'), ('192.168.127.129', '99999')])
# # Xây dựng flow ID dựa trên thông tin đã sắp xếp
# flow_id = f"{sorted_pair1[0][0]}_{sorted_pair1[0][1]}_{sorted_pair1[1][0]}_{sorted_pair1[1][1]}_tcp"
# print(flow_id)

ongoing_in_flows = []
incoming_in_flows = []

magnitude = (
        np.var(ongoing_in_flows if len(ongoing_in_flows) > 0 else [0]) + 
        np.var(incoming_in_flows if len(incoming_in_flows) > 0 else [0])
    )
print(magnitude)

print('covar: ', np.cov([0]))
if 0.000000000000000000 == 0.0:
    print(datetime.now().timestamp())
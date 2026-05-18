import openpyxl
import json
import os
import sys

def process_ase11():
    file_path = 'data/raw/15-ASE-TARA1.4.xlsx'
    print(f"Loading: {file_path}")
    sys.stdout.flush()
    
    wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
    print(f"Workbook loaded")
    sys.stdout.flush()
    
    ws = wb['TARA 分析汇总']
    print(f"Sheet loaded")
    sys.stdout.flush()
    
    col_mapping = {
        3: '功能',
        8: '资产',
        9: '资产类型',
        34: '损害场景',
        17: '威胁场景',
        31: '攻击路径',
        36: '安全',
        38: '财产',
        40: '操作',
        42: '隐私',
        19: '暴露时间',
        21: '专业经验',
        23: '所需信息',
        25: '机会窗口',
        27: '所需设备',
            
    }
    
    results = []
    row_idx = 0
    
    for row in ws.iter_rows(min_row=3):
        row_idx += 1
        func_id = row[0].value
        if not func_id:
            break
        
        item = {}
        for col_idx, name in col_mapping.items():
            if col_idx <= len(row):
                value = row[col_idx - 1].value
                if value and isinstance(value, str) and value.startswith('='):
                    value = ""
                if value == 0:
                    item[name] = "0"
                elif value:
                    item[name] = str(value)
                else:
                    item[name] = ""
        
        security_attrs = []
        attr_cols = [(10, '机密性'), (11, '完整性'), (12, '可用性'), 
                     (13, '不可抵赖性'), (14, '真实性'), (15, '权限属性')]
        for col_idx, attr_name in attr_cols:
            if col_idx <= len(row):
                val = row[col_idx - 1].value
                if val and val != '-' and str(val).strip():
                    security_attrs.append(attr_name)
        
        item['安全属性'] = ','.join(security_attrs)
        
        results.append(item)
        
        if row_idx % 1000 == 0:
            print(f"Processed {row_idx} rows...")
            sys.stdout.flush()
    
    wb.close()
    print(f"Total rows: {len(results)}")
    sys.stdout.flush()
    
    output_dir = 'data/processed/15-ASE-TARA1.4'
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, '15-ASE-TARA1.4.json')
    
    print(f"Writing to: {output_path}")
    sys.stdout.flush()
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    print(f"Done! Output: {output_path}")
    sys.stdout.flush()
    
    return results

if __name__ == '__main__':
    process_ase11()
/* lab3 mtest
 * @author: chenge.sun(516030910421)
 */

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/io.h>

static struct proc_dir_entry *entry = NULL;

static const char * FIND_PAGE = "findpage";
static const char * WRITE_VAL = "writeval";

/* Print all vma of the current process*/
static void mtest_list_vma(void) {
	struct mm_struct *mm = current->mm;  
    	struct vm_area_struct *vma;       
    	
	down_read(&mm->mmap_sem); 
	printk(KERN_INFO "[mtest] listvma:\n");
    	for (vma = mm->mmap; vma; vma = vma->vm_next) {  
        	printk("VMA 0x%lx-0x%lx ", vma->vm_start, vma->vm_end);  
        	(vma->vm_flags & VM_READ) ? printk("r") : printk("-");
        	(vma->vm_flags & VM_WRITE) ? printk("w") : printk("-");
        	(vma->vm_flags & VM_EXEC) ? printk("x") : printk("-");  
        	printk("\n");  
    	}  
    	up_read(&mm->mmap_sem); 	
}	

/* Find va->pa translation
 * @input: virtual address
 * @output: target page
 */
static struct page *  mtest_find_page_core(unsigned long addr) {
	pgd_t * pgd = NULL;
	p4d_t * p4d = NULL;
	pud_t * pud = NULL;
	pmd_t * pmd = NULL;
	pte_t * pte = NULL;
	struct mm_struct * mm = current->mm;
	struct page * page = NULL;

	if (!mm) goto rtn;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)) {
		printk("[mtest] pgd not present.\n");
		goto rtn;
	}
	p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
		printk("[mtest] p4d not present.\n");
		goto rtn;
	}
	pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
		printk("[mtest] pud not present.\n");
		goto rtn;
	}
	pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
		printk("[mtest] pmd not present.\n");
		goto rtn;
	}
	pte = pte_offset_kernel(pmd, addr);
	if (!pte_present(*pte)) {
		printk("[mtest] pte not present.\n");
		goto rtn;
	}
	page = pte_page(*pte);
	if (!page) {
		printk("[mtest] page not present.\n");
	}
rtn:
	return page;
}

static void mtest_find_page(unsigned long addr) { 
	struct page * page = mtest_find_page_core(addr);
	unsigned long long pma = 0;
	if(!page) {
		printk("[mtest] tanslation for vma 0x%lx not found.\n",addr);
		return;
	}
	pma = (page_to_phys(page) & PAGE_MASK) | (addr & ~PAGE_MASK);
	printk("[mtest] vma 0x%lx -> pma 0x%llx.\n", addr, pma);
}

/*Write val to the specified address*/
static void mtest_write_val(unsigned long addr, unsigned long val) {
	struct vm_area_struct * vma = find_vma(current->mm, addr);
	struct page * page = NULL;
	unsigned long * kernel_vma = NULL;

	if (!vma || vma->vm_start > addr) {
		printk("[mtest] vma 0x%lx is not valid.\n", addr);
		return;
	}
	if (!(vma->vm_flags & VM_WRITE)) {
		printk("[mtest] vma 0x%lx is not writable.\n", addr);
		return;
	}
	page  = mtest_find_page_core(addr);
	if (!page) {
		printk("[mtest] page corresponding to address 0x%lx dosen't exist.\n", addr);
		return;
	}

	kernel_vma = (unsigned long *) page_address(page);
	kernel_vma += (addr&~PAGE_MASK);
	*kernel_vma = val;
	printk("[mtest] write 0x%lx to address 0x%lx.\n", val, (unsigned long) kernel_vma);
}

/* 
 * @input: string
 * @output: the first token after blankspace
 * @input: null
 * @output: the next token after blankspace
 */
static char * split(char* str) {
	char * ret = NULL;
	int idx = 0;
	int ret_idx = 0;
	static char * next = NULL;
       	if (str) {
		next = str;
	}
	ret  = (char*) kzalloc(sizeof(char) * (strlen(next)+1), GFP_KERNEL);	
	while(idx<strlen(next) && next[idx] == ' ') 
		idx++;
	while (idx<strlen(next) && next[idx] != ' ') {
		ret[ret_idx] = next[idx];
		idx++;
		ret_idx++;
	}
	ret[ret_idx] = '\0';
	next = next+idx;
	return ret;
}

static ssize_t mtest_proc_write(struct file * file, const char __user * ubuf, size_t count, loff_t * ppos) {
	char *buf = NULL;
	char *pch = NULL;
	unsigned long addr = 0;
	unsigned long val = 0;

	if (*ppos > 0)
		return -EFAULT;
	buf = (char*) kzalloc(sizeof(char) * count, GFP_KERNEL);
	if (copy_from_user(buf, ubuf, count)) {
		if (!buf)
			return -EFAULT;	
	}
	pch = split(buf);
	if (pch != NULL) {
		if (!strcmp(FIND_PAGE, pch)) {
			pch = split(NULL);
			kstrtoul(pch, 16, &addr);
			mtest_find_page(addr);
		}
		else if (!strcmp(WRITE_VAL, pch)){
			pch = split(NULL);
			kstrtoul(pch, 16, &addr);
			pch = split(NULL);
			kstrtoul(pch, 10, &val);
			mtest_write_val(addr, val);
		}
		else {
			mtest_list_vma();
		}
	}
	*ppos = strlen(buf);
	if (buf) 
		kfree(buf);
	return *ppos;
}

static struct file_operations proc_mtest_operations = {
	.write = mtest_proc_write,
};

static int __init mtest_init(void) {
	entry = proc_create("mtest", 0660, NULL, &proc_mtest_operations);
	if (!entry)
		return -1;
	printk(KERN_INFO "[mtest] hello\n");
	return 0;
}

static void __exit mtest_exit(void) {
	proc_remove(entry);
	printk(KERN_INFO "[mtest] goodbye\n");
}

module_init(mtest_init);
module_exit(mtest_exit);
